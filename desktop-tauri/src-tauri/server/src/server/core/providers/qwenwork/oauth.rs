//! 千问办公的 **OAuth Device Flow + PKCE**（登录 / 换票 / 账号信息）。
//!
//! ── 为什么这条链能完全脱离桌面客户端 ────────────────────────
//! 授权页在网关上（`/device/selectAccounts`），它 302 到 `qwenwork.cn` 的标准
//! OAuth 授权端点；**取票端点不需要 Authorization** —— 持有 `nonce` + `verifier`
//! 即可拿票（参考实现 `qwenwork/login.js` 的实测注释）。所以本机不用监听
//! 回调端口、壳侧不用捕获自定义协议：用户完成浏览器登录后，我们自己轮询取票。
//!
//! ```text
//!   1. 本地生成 PKCE（verifier + S256 challenge）与 nonce、machineId
//!   2. 打开 https://gateway.qwenwork.cn/device/selectAccounts?challenge=…
//!   3. 授权结果由**服务端**记在 device flow 状态里，回调落
//!      gateway.qwenwork.cn/oauth/callback —— 不回到本机
//!   4. 轮询 GET /api/v1/deviceToken/poll?nonce=&verifier=&challenge_method=S256
//!      pending → 404 {}；成功 → { device_token, refresh_token, expires_at, … }
//! ```
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::server::core::auth_http::send_raw;
use crate::server::errors::GatewayError;

use crate::server::core::providers::cosy;

use super::constants;

/// 一次进行中的 device flow（只放进程内：登录窗口 5 分钟，且发起与轮询
/// 必然是同一个前端会话）
pub struct DeviceLogin {
    pub nonce: String,
    pub verifier: String,
    pub challenge: String,
    pub machine_id: String,
    started: Instant,
}

/// 取票结果
pub enum PollOutcome {
    /// 还没授权（上游 404）
    Pending,
    /// 拿到票
    Authorized(TokenBundle),
}

/// 一次换票的结果
#[derive(Clone)]
pub struct TokenBundle {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub refresh_expires_at: i64,
}

/// 账号信息（account-context 的归一）
pub struct AccountInfo {
    pub uid: String,
    pub nickname: String,
    pub username: String,
    pub email: String,
    pub tier: String,
    pub plan_name: String,
}

impl DeviceLogin {
    /// 是否已超出 5 分钟窗口（上游的 nonce 同样会作废）
    pub fn expired(&self) -> bool {
        self.started.elapsed() >= Duration::from_millis(constants::DEVICE_FLOW_TIMEOUT_MS)
    }
}

/// 开一次登录：返回流程状态与给用户打开的授权地址。
pub fn start() -> Result<(DeviceLogin, String), GatewayError> {
    let verifier = random_token(43)?;
    let challenge = {
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    };
    let nonce = cosy::random_uuid()?;
    // 每个账号一份机器码：它与 token 配套进签名，共用会让服务端把两个账号
    // 关联到同一台设备
    let machine_id = cosy::random_uuid()?;
    let url = format!(
        "{}{}?challenge={}&challenge_method=S256&nonce={}&machine_id={}&client_id={}&redirect_uri={}",
        constants::GATEWAY,
        constants::DEVICE_SELECT_PATH,
        urlencode(&challenge),
        urlencode(&nonce),
        urlencode(&machine_id),
        urlencode(constants::OAUTH_CLIENT_ID),
        urlencode(constants::OAUTH_REDIRECT_URI),
    );
    Ok((
        DeviceLogin {
            nonce,
            verifier,
            challenge,
            machine_id,
            started: Instant::now(),
        },
        url,
    ))
}

/// 查一次取票端点（只查一次，等待交给调用方 —— 与参考实现同一取舍）。
pub async fn poll(login: &DeviceLogin) -> Result<PollOutcome, GatewayError> {
    if login.expired() {
        return Err(GatewayError::with_status(400, "千问办公登录超时（5 分钟），请重新发起"));
    }
    let url = format!(
        "{}{}?nonce={}&verifier={}&challenge_method=S256",
        constants::GATEWAY,
        constants::DEVICE_POLL_PATH,
        urlencode(&login.nonce),
        urlencode(&login.verifier),
    );
    let headers = vec![
        ("User-Agent".to_string(), constants::USER_AGENT.to_string()),
        ("X-Request-Id".to_string(), cosy::random_uuid()?),
    ];
    let response = send_raw("GET", &url, None, &headers, None, Some(20_000))
        .await
        .map_err(|error| {
            GatewayError::with_status(502, format!("千问办公取票请求失败: {error}"))
        })?;
    if response.status == 404 {
        return Ok(PollOutcome::Pending);
    }
    if !(200..300).contains(&response.status) {
        return Err(GatewayError::with_status(
            502,
            format!("千问办公取票失败（HTTP {}）", response.status),
        ));
    }
    let payload = response.payload.unwrap_or(Value::Null);
    let access_token = str_field(&payload, "token");
    let access_token = if access_token.is_empty() {
        str_field(&payload, "device_token")
    } else {
        access_token
    };
    if access_token.is_empty() {
        // 没有 token 也没 404：上游在等你（参考实现同款判定）
        return Ok(PollOutcome::Pending);
    }
    // 服务端可能回显 nonce / challenge；确实回显了才比对（字段缺失时硬判
    // 不等会把一次正常登录报成失败）
    if let Some(echo) = payload.get("nonce").and_then(Value::as_str) {
        if echo != login.nonce {
            return Err(GatewayError::with_status(
                400,
                "device flow 绑定校验失败（nonce 不一致）",
            ));
        }
    }
    if let Some(echo) = payload.get("code_challenge").and_then(Value::as_str) {
        if echo != login.challenge {
            return Err(GatewayError::with_status(
                400,
                "device flow 绑定校验失败（challenge 不一致）",
            ));
        }
    }
    let refresh_token = str_field(&payload, "refresh_token");
    if refresh_token.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "千问办公取票响应里没有 refresh_token，该账号后续无法续期",
        ));
    }
    Ok(PollOutcome::Authorized(TokenBundle {
        expires_at: expires_at_of(&payload, &access_token),
        refresh_expires_at: time_field(&payload, "refresh_token_expires_at"),
        access_token,
        refresh_token,
    }))
}

/// 用 refresh token 换一对新票。
///
/// **轮换**：上游同时下发新的 refresh token，必须写回记录（参考实现实测旧
/// token 不会立即作废，但那不是设计保证）。
pub async fn refresh(refresh_token: &str) -> Result<TokenBundle, GatewayError> {
    if refresh_token.trim().is_empty() {
        return Err(GatewayError::with_status(
            401,
            "千问办公账号缺少 refresh_token，无法续期，请重新登录",
        ));
    }
    let url = format!("{}{}", constants::GATEWAY, constants::REFRESH_PATH);
    let headers = vec![
        ("User-Agent".to_string(), constants::USER_AGENT.to_string()),
        ("X-Request-Id".to_string(), cosy::random_uuid()?),
        (
            "Login-Version".to_string(),
            constants::LOGIN_VERSION.to_string(),
        ),
    ];
    let body = json!({ "refresh_token": refresh_token, "target": "c" });
    let response = send_raw("POST", &url, Some(&body), &headers, None, Some(30_000))
        .await
        .map_err(|error| {
            GatewayError::with_status(502, format!("千问办公换票请求失败: {error}"))
        })?;
    let payload = response.payload.unwrap_or(Value::Null);
    let access_token = str_field(&payload, "device_token");
    let access_token = if access_token.is_empty() {
        str_field(&payload, "token")
    } else {
        access_token
    };
    if access_token.is_empty() {
        let code = payload
            .get("errorCode")
            .or_else(|| payload.get("error"))
            .map(|value| value.to_string())
            .unwrap_or_else(|| format!("HTTP {}", response.status));
        let detail = payload
            .get("errorMessage")
            .or_else(|| payload.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("");
        return Err(GatewayError::with_status(
            401,
            format!(
                "千问办公换票失败（{code}{}），请重新登录",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            ),
        ));
    }
    Ok(TokenBundle {
        expires_at: expires_at_of(&payload, &access_token),
        refresh_expires_at: time_field(&payload, "refresh_token_expires_at"),
        access_token,
        // 非空才覆盖（上游可能省略；整包替换会让账号失去续期能力）
        refresh_token: {
            let fresh = str_field(&payload, "refresh_token");
            if fresh.is_empty() {
                refresh_token.to_string()
            } else {
                fresh
            }
        },
    })
}

/// 读账号信息（uid / 昵称 / 套餐）。uid 是签名的**硬前提**。
pub async fn account_context(access_token: &str) -> Result<AccountInfo, GatewayError> {
    if access_token.trim().is_empty() {
        return Err(GatewayError::with_status(401, "千问办公账号缺少访问令牌"));
    }
    let url = format!("{}{}", constants::GATEWAY, constants::ACCOUNT_CONTEXT_PATH);
    let headers = vec![
        ("User-Agent".to_string(), constants::USER_AGENT.to_string()),
        ("Authorization".to_string(), format!("Bearer {access_token}")),
    ];
    let response = send_raw("GET", &url, None, &headers, None, Some(20_000))
        .await
        .map_err(|error| {
            GatewayError::with_status(502, format!("千问办公账号信息请求失败: {error}"))
        })?;
    if !(200..300).contains(&response.status) {
        return Err(GatewayError::with_status(
            502,
            format!("千问办公账号信息失败（HTTP {}）", response.status),
        ));
    }
    let payload = response.payload.unwrap_or(Value::Null);
    let data = payload.get("data").cloned().unwrap_or(payload);
    let user = data.get("user").cloned().unwrap_or_else(|| data.clone());
    let plan = data.get("plan").cloned().unwrap_or(Value::Null);
    let uid = first_str(&user, &["id", "user_id", "uid"]);
    if uid.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "千问办公账号信息里没有 uid（无法签名），该账号不可用",
        ));
    }
    Ok(AccountInfo {
        uid,
        nickname: {
            let name = first_str(&user, &["name", "username"]);
            if name.is_empty() {
                first_str(&user, &["user_name"])
            } else {
                name
            }
        },
        username: first_str(&user, &["username", "user_name"]),
        // account-context 里的邮箱是**占位符**（`phone_<uid>@phone.local`，真实
        // 手机号在 identities 的 `c_site_user` 里）。它不是用户的邮箱，存下来
        // 只会在账号行上显示一串内部格式 —— 如实留空。
        email: {
            let email = first_str(&user, &["email"]);
            if email.ends_with("@phone.local") {
                String::new()
            } else {
                email
            }
        },
        tier: {
            let tier = first_str(&user, &["tier"]);
            if tier.is_empty() {
                first_str(&plan, &["name"])
            } else {
                tier
            }
        },
        plan_name: first_str(&plan, &["name"]),
    })
}

/// 读真实手机号（`account-context` 只有占位邮箱）。失败返回 `None`，不阻断登录。
pub async fn identities_phone(access_token: &str) -> Option<String> {
    let url = format!("{}{}", constants::GATEWAY, constants::IDENTITIES_PATH);
    let headers = vec![
        ("User-Agent".to_string(), constants::USER_AGENT.to_string()),
        ("Authorization".to_string(), format!("Bearer {access_token}")),
    ];
    let response = send_raw("GET", &url, None, &headers, None, Some(15_000))
        .await
        .ok()?;
    let payload = response.payload?;
    let user = payload.get("c_site_user")?;
    let number = user
        .get("phone_number")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if number.is_empty() {
        return None;
    }
    let code = user
        .get("phone_country_code")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    Some(if code.is_empty() {
        number.to_string()
    } else {
        format!("{code}{number}")
    })
}

/// 手机号脱敏（157****1251）—— PII 只按脱敏形式进公开形态。
pub fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() < 7 {
        return phone.to_string();
    }
    let head: String = chars.iter().take(3).collect();
    let tail: String = chars.iter().rev().take(4).collect::<Vec<&char>>().into_iter().rev().cloned().collect();
    format!("{head}****{tail}")
}

// ─── 小工具 ─────────────────────────────────────────────────

fn str_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn first_str(value: &Value, keys: &[&str]) -> String {
    for key in keys {
        let text = str_field(value, key);
        if !text.is_empty() {
            return text;
        }
    }
    String::new()
}

/// `expires_at` 可能是 ISO 串，也可能是 JWT 的 `exp`（读不到就给 0）
fn expires_at_of(payload: &Value, access_token: &str) -> i64 {
    let explicit = time_field(payload, "expires_at");
    if explicit > 0 {
        return explicit;
    }
    jwt_exp(access_token).unwrap_or(0)
}

/// ISO 时间串 / 毫秒数 → 毫秒（解析失败给 0）
fn time_field(payload: &Value, key: &str) -> i64 {
    match payload.get(key) {
        Some(Value::Number(number)) => number
            .as_i64()
            .filter(|value| *value > 0)
            .map(|value| if value < 10_000_000_000 { value * 1000 } else { value })
            .unwrap_or(0),
        Some(Value::String(text)) => chrono::DateTime::parse_from_rfc3339(text.trim())
            .map(|value| value.timestamp_millis())
            .unwrap_or(0),
        _ => 0,
    }
}

/// 从 JWT 的 payload 里读 `exp`（毫秒）；不是 JWT 给 None
fn jwt_exp(token: &str) -> Option<i64> {
    let part = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .ok()?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    let exp = value.get("exp")?.as_i64()?;
    Some(exp * 1000)
}

/// 43 个 unreserved 字符（PKCE 允许 43..128；固定下界即可）
fn random_token(length: usize) -> Result<String, GatewayError> {
    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| GatewayError::with_status(500, "无法生成登录随机串"))?;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut out = String::with_capacity(length);
    for byte in bytes {
        out.push(ALPHABET[(byte as usize) % ALPHABET.len()] as char);
    }
    Ok(out)
}

/// 查询串转义（只用于 UUID / base64 这些安全字符，但统一走一遍更稳）
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_url_carries_pkce_and_client_id() {
        let (login, url) = start().expect("start");
        assert!(url.starts_with("https://gateway.qwenwork.cn/device/selectAccounts?"));
        assert!(url.contains("challenge_method=S256"));
        assert!(url.contains(constants::OAUTH_CLIENT_ID));
        assert!(url.contains("redirect_uri=qwenwork-cn%3A%2F%2F"));
        assert!(url.contains(&login.nonce));
        assert!(url.contains(&login.machine_id));
        assert!(!login.verifier.is_empty());
        assert_ne!(login.verifier, login.challenge);
    }

    #[test]
    fn phone_masking_keeps_head_and_tail() {
        assert_eq!(mask_phone("15712341251"), "157****1251");
        assert_eq!(mask_phone("123"), "123");
    }

    #[test]
    fn jwt_exp_is_read_when_present() {
        // {"exp":1700000000} 的 base64url
        let token = "x.eyJleHAiOjE3MDAwMDAwMDB9.y";
        assert_eq!(jwt_exp(token), Some(1_700_000_000_000));
        assert_eq!(jwt_exp("not-a-jwt"), None);
    }
}
