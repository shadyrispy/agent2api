//! 千问办公账号的凭证读取（会话形态 → 签名素材）。
//!
//! 会话由 `AccountStore::session_from_record` 构造：通用键是
//! `auth.accessToken` / `auth.expiresAt` / `account.uid`；本家特有的
//! `machineId` 由 `session_from_record` 的 provider 分支注入（与 ZCode /
//! Antigravity / OfficeAce 同一手法，对别家逐字不变）。
//!
//! ── 为什么 uid 是硬前提 ─────────────────────────────────────
//! COSY 签名把 uid 加密进身份 JSON，缺了它请求根本签不出来；上游也会在
//! `account-context` 这一步就暴露（读不到 uid = 账号建不起来）。所以
//! [`from_session`] 对空 uid 直接报 400，而不是让第一次转发才失败。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use serde_json::Value;

use crate::server::errors::GatewayError;

/// 一条千问办公账号的签名素材
#[derive(Debug)]
pub struct QwenworkCredentials {
    /// account-context 读到的 uid（签名必需）
    pub uid: String,
    /// device token
    pub access_token: String,
    /// refresh token（轮换；续期后必须写回）
    pub refresh_token: String,
    /// 每账号一份机器码
    pub machine_id: String,
    /// access token 到期时刻（毫秒，0 = 未知）
    pub expires_at: i64,
}

impl QwenworkCredentials {
    /// 是否已过期或临期（提前 5 分钟，与参考实现同一阈值）
    pub fn expiring(&self) -> bool {
        self.expires_at <= 0
            || crate::server::logging::now_ms() + 300_000 >= self.expires_at
    }
}

fn text_at(value: &Value, path: &[&str]) -> String {
    let mut current = value;
    for key in path {
        current = match current.get(*key) {
            Some(next) => next,
            None => return String::new(),
        };
    }
    current.as_str().map(str::trim).unwrap_or("").to_string()
}

/// 从会话形态读凭证（`build_chat_request` / 目录 / 额度共用）。
pub fn from_session(session: &Value) -> Result<QwenworkCredentials, GatewayError> {
    let uid = text_at(session, &["account", "uid"]);
    let access_token = text_at(session, &["auth", "accessToken"]);
    let refresh_token = text_at(session, &["auth", "refreshToken"]);
    let machine_id = text_at(session, &["machineId"]);
    let expires_at = session
        .get("auth")
        .and_then(|auth| auth.get("expiresAt"))
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value > 0.0)
        .map(|value| value as i64)
        .unwrap_or(0);
    if uid.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "千问办公账号缺少 uid（签名必需），请重新登录",
        ));
    }
    if access_token.is_empty() {
        return Err(GatewayError::with_status(
            401,
            "千问办公账号缺少访问令牌，请重新登录",
        ));
    }
    Ok(QwenworkCredentials {
        uid,
        access_token,
        refresh_token,
        machine_id,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_uid_and_token_from_session_shape() {
        let session = json!({
            "auth": { "accessToken": "at", "refreshToken": "rt", "expiresAt": 1_700_000_000_000_i64 },
            "account": { "uid": "u1" },
            "machineId": "m1"
        });
        let credentials = from_session(&session).expect("credentials");
        assert_eq!(credentials.uid, "u1");
        assert_eq!(credentials.access_token, "at");
        assert_eq!(credentials.refresh_token, "rt");
        assert_eq!(credentials.machine_id, "m1");
        assert_eq!(credentials.expires_at, 1_700_000_000_000);
    }

    #[test]
    fn missing_uid_is_a_400_not_a_late_failure() {
        let session = json!({ "auth": { "accessToken": "at" } });
        let error = from_session(&session).expect_err("必须报错");
        assert_eq!(error.status_code, 400);
        assert!(error.message.contains("uid"));
    }
}
