//! 千问办公的 COSY 请求构造（纯本地签名，**不需要官方 wasm / 客户端**）。
//!
//! 算法本体在 `providers::cosy`（与 Qoder 共用）。本文件只放千问特有的
//! 身份 JSON 与请求头。
//!
//! ── 历史（别按旧资料改回去）─────────────────────────────────
//! 本通道早期实现必须调 `qoder_auth_wasm_bg.wasm` 生成请求体，理由是
//! 「本地自实现的编码会被服务端拒（400 Invalid agent chat JSON body）」。
//! 那是 2026-09-23 的结论；2026-10-14 用与 Qoder 共用的本地签名实测
//! `gateway.qwenwork.cn` 返回 200、19 帧正常出流、usage 完整
//! （见参考实现 `qwenwork/cosy-sign.js` 的文件头）。所以**不引入 wasm 资产**：
//! 它是客户端二进制、卸载即失效，而且每请求起子进程会让签名变成毫秒级 IO。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use crate::server::errors::GatewayError;

use crate::server::core::providers::cosy::{self, CosySession};

use super::constants;

/// 一次请求的签名素材
pub struct QwenworkIdentity<'a> {
    /// account-context 读到的 uid（**签名必需**，没有它发不出请求）
    pub uid: &'a str,
    /// device token（进身份 JSON 的 `security_oauth_token`）
    pub token: &'a str,
    /// 每账号一份机器码（共用会让服务端把两个账号关联到同一台设备）
    pub machine_id: &'a str,
}

/// 身份 JSON：**键必须字母序**（参考实现 `sortedJson`），且字段集合与
/// 官方 `generate_runtime_auth_fields` 的输入形状一致。
///
/// 与 Qoder 的字段集合不同（那是 uid / security_oauth_token / name / aid / email），
/// 所以两家各写一份 JSON，只共用加密与签名算法。
fn identity_json(identity: &QwenworkIdentity<'_>) -> String {
    format!(
        "{{\"data_policy_agreed\":true,\"organization_id\":\"\",\"organization_tags\":\"\",\
         \"security_oauth_token\":{},\"uid\":{}}}",
        cosy::json_text(identity.token),
        cosy::json_text(identity.uid),
    )
}

/// 构造一次聊天请求的全部头。`body` 是**已编码**的请求体。
///
/// 头集合逐字对齐参考实现 `buildHeaders`（`qwenwork/cosy-sign.js`）：
/// 少了 `Cosy-Business-*` / `Cosy-Scene` 会被按别的业务线处理，
/// `x-model-key` 只给 body 不给头时上游仍按 auto 走（与 Qoder 同一个坑）。
pub fn build_chat_headers(
    body: &[u8],
    request_url: &str,
    identity: &QwenworkIdentity<'_>,
    model_key: &str,
) -> Result<Vec<(String, String)>, GatewayError> {
    if identity.uid.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "千问办公账号缺少用户标识（uid），无法签名 —— 请重新登录",
        ));
    }
    if identity.token.is_empty() {
        return Err(GatewayError::with_status(
            401,
            "千问办公账号缺少访问令牌，请重新登录",
        ));
    }

    let session = CosySession::new(&identity_json(identity))?;
    let payload = session.payload_b64(constants::COSY_VERSION);
    let date = cosy::now_timestamp();
    let sig_path = cosy::signature_path(request_url)?;
    let signature = session.signature(&payload, &date, body, &sig_path);

    let headers: Vec<(String, String)> = vec![
        ("cosy-data-policy".to_string(), "agree".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
        ("cosy-clienttype".to_string(), constants::CLIENT_TYPE.to_string()),
        ("cosy-date".to_string(), date),
        ("cosy-user".to_string(), identity.uid.to_string()),
        ("cosy-key".to_string(), session.cosy_key),
        ("cache-control".to_string(), "no-cache".to_string()),
        ("accept".to_string(), "text/event-stream".to_string()),
        (
            "authorization".to_string(),
            cosy::compose_bearer(&payload, &signature),
        ),
        ("cosy-version".to_string(), constants::COSY_VERSION.to_string()),
        ("cosy-machineid".to_string(), identity.machine_id.to_string()),
        ("login-version".to_string(), constants::LOGIN_VERSION.to_string()),
        ("user-agent".to_string(), constants::USER_AGENT.to_string()),
        ("cosy-scene".to_string(), constants::SCENE.to_string()),
        (
            "cosy-business-product".to_string(),
            constants::BUSINESS_PRODUCT.to_string(),
        ),
        (
            "cosy-business-type".to_string(),
            constants::BUSINESS_TYPE.to_string(),
        ),
        ("x-model-key".to_string(), model_key.to_string()),
        ("x-model-source".to_string(), "system".to_string()),
        ("x-request-id".to_string(), session.request_id.clone()),
    ];
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 身份 JSON 的键顺序是契约（参与 AES 密文与签名）。
    #[test]
    fn identity_json_keeps_sorted_keys() {
        let text = identity_json(&QwenworkIdentity {
            uid: "u1",
            token: "t1",
            machine_id: "m1",
        });
        assert_eq!(
            text,
            "{\"data_policy_agreed\":true,\"organization_id\":\"\",\"organization_tags\":\"\",\
             \"security_oauth_token\":\"t1\",\"uid\":\"u1\"}"
        );
    }

    /// 头集合里该有的都有（少一个上游就换业务线或降级成 auto）。
    #[test]
    fn chat_headers_carry_the_required_set() {
        let headers = build_chat_headers(
            b"encoded",
            "https://gateway.qwenwork.cn/algo/api/v2/service/pro/sse/agent_chat_generation?Encode=1",
            &QwenworkIdentity {
                uid: "u1",
                token: "t1",
                machine_id: "m1",
            },
            "pro",
        )
        .expect("headers");
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        for required in [
            "authorization",
            "cosy-key",
            "cosy-user",
            "cosy-version",
            "cosy-machineid",
            "cosy-scene",
            "cosy-business-product",
            "cosy-business-type",
            "x-model-key",
            "content-type",
        ] {
            assert!(names.contains(&required), "缺少头 {required}");
        }
        let auth = headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        assert!(auth.starts_with("Bearer COSY."));
        assert_eq!(auth.split('.').count(), 3, "COSY 信封是三段");
    }
}
