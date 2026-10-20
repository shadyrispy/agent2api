//! Qoder 的 COSY 请求签名与请求头（**协议算法**在 `providers::cosy`，两家共用）。
//!
//! 本文件只留 Qoder 特有的部分：`cosyVersion` 常量、客户端身份头、身份 JSON 的
//! 字段集合。算法本体（AES/RSA/MD5/请求体编码）见
//! [`crate::server::core::providers::cosy`] —— 千问办公用的是同一套栈，
//! 写在那边是为了不出现第二份必然漂移的实现。
//!
//! ── 请求顺序 ──────────────────────────────────────────────
//! **请求体参与签名**，所以调用方必须先 `encode_body` 再调 `build_auth_headers`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use crate::server::errors::GatewayError;

use crate::server::core::providers::cosy::{self, CosySession};

pub use crate::server::core::providers::cosy::{encode_body, random_uuid, signature_path};

/// 推理网关（`/algo/...`）使用的 COSY 协议版本
pub const GATEWAY_COSY_VERSION: &str = "1.1.38";
/// 客户端类型标识（桌面端为 0，这里沿用 CLI 形态，与源项目一致）
pub const CLIENT_TYPE: &str = "5";
/// 数据策略：不同意用于训练
pub const DATA_POLICY: &str = "disagree";
/// 登录版本标识
pub const LOGIN_VERSION: &str = "v2";

/// 网关用它区分客户端形态（COSY 头 `Cosy-Machinetype`）
const MACHINE_TYPE: &str = "5";

/// `Cosy-Clientip`：本机回环（源实现写死该值）
const CLIENT_IP: &str = "127.0.0.1";

/// 一次签名所需的身份素材（对应源实现 `buildAuthHeaders` 的 creds 参数）。
pub struct CosyIdentity<'a> {
    /// 账号在 Qoder 侧的 uid（源实现 `uid`）
    pub user_id: &'a str,
    /// access token（源实现 `security_oauth_token`）
    pub auth_token: &'a str,
    /// 昵称（可为空）
    pub name: &'a str,
    /// 邮箱（可为空）
    pub email: &'a str,
    /// 机器标识（COSY 头里要带，且参与「同一账号不同设备」的判定）
    pub machine_id: &'a str,
}

/// 构造一次请求所需的全部 COSY 头。
///
/// `body` 是**已编码**的请求体（GET 类请求传 `None`）。签名覆盖它，
/// 所以调用方必须先 [`encode_body`] 再调本函数 —— 顺序颠倒会得到一个
/// 「签名不匹配」的上游错误，且无法从错误里看出原因。
pub fn build_auth_headers(
    body: Option<&[u8]>,
    request_url: &str,
    identity: &CosyIdentity<'_>,
) -> Result<Vec<(String, String)>, GatewayError> {
    if identity.user_id.is_empty() {
        return Err(GatewayError::with_status(400, "Qoder 账号缺少用户标识，无法签名"));
    }
    if identity.auth_token.is_empty() {
        return Err(GatewayError::with_status(401, "Qoder 账号缺少访问令牌，请重新登录"));
    }

    // 身份 JSON：**键顺序照抄源实现**（uid / security_oauth_token / name / aid / email）。
    //
    // 为什么手写而不是 `json!`：本项目的 serde_json 未开 `preserve_order`，
    // `Value::Object` 是按键排序的 BTreeMap —— 键序变了，AES 密文与签名就都与
    // 源实现不同。见 `providers::cosy` 模块头的说明。
    let user_info = format!(
        "{{\"uid\":{},\"security_oauth_token\":{},\"name\":{},\"aid\":\"\",\"email\":{}}}",
        cosy::json_text(identity.user_id),
        cosy::json_text(identity.auth_token),
        cosy::json_text(identity.name),
        cosy::json_text(identity.email),
    );
    let session = CosySession::new(&user_info)?;
    let payload = session.payload_b64(GATEWAY_COSY_VERSION);
    let timestamp = cosy::now_timestamp();
    let sig_path = cosy::signature_path(request_url)?;
    let body_bytes = body.unwrap_or(&[]);

    let signature = session.signature(&payload, &timestamp, body_bytes, &sig_path);
    let body_hash = CosySession::body_hash(body_bytes);

    let headers: Vec<(String, String)> = vec![
        (
            "Authorization".to_string(),
            cosy::compose_bearer(&payload, &signature),
        ),
        ("Cosy-Key".to_string(), session.cosy_key),
        ("Cosy-User".to_string(), identity.user_id.to_string()),
        ("Cosy-Date".to_string(), timestamp),
        ("Cosy-Version".to_string(), GATEWAY_COSY_VERSION.to_string()),
        ("Cosy-Machineid".to_string(), identity.machine_id.to_string()),
        ("Cosy-Machinetoken".to_string(), identity.machine_id.to_string()),
        ("Cosy-Machinetype".to_string(), MACHINE_TYPE.to_string()),
        ("Cosy-Machineos".to_string(), cosy::machine_os()),
        ("Cosy-Clienttype".to_string(), CLIENT_TYPE.to_string()),
        ("Cosy-Clientip".to_string(), CLIENT_IP.to_string()),
        ("Cosy-Bodyhash".to_string(), body_hash),
        ("Cosy-Bodylength".to_string(), body_bytes.len().to_string()),
        ("Cosy-Sigpath".to_string(), sig_path),
        ("Cosy-Data-Policy".to_string(), DATA_POLICY.to_string()),
        ("Cosy-Organization-Id".to_string(), String::new()),
        ("Cosy-Organization-Tags".to_string(), String::new()),
        ("Login-Version".to_string(), LOGIN_VERSION.to_string()),
        ("X-Request-Id".to_string(), session.request_id),
    ];
    Ok(headers)
}
