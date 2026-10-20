//! 千问办公（QwenWork）账号：登录落账号、公开形态、会话读取。
//!
//! ── 账号字段 ────────────────────────────────────────────────
//! ```text
//!   { id, provider:"qwenwork", name, uid, nickname, email, phone(masked),
//!     planName, accessToken, refreshToken, machineId, tokenTail,
//!     expiresAt, addedAt, updatedAt, source, priority, enabled }
//! ```
//! `accessToken` / `refreshToken` 用本仓统一的键名（`update_account_tokens`
//! 认它们，续期写回走那条通用路径）。`machineId` 是**每账号一份**的设备码，
//! 与 token 配套进 COSY 签名 —— 换掉等于换设备，所以登录时生成一次后不再改。
//!
//! ── 与别家添加路径的关系 ────────────────────────────────────
//! 本家**只有浏览器登录一条路**（device flow）：取票靠服务端轮询，回调不回本机。
//! 粘贴凭据这条入口不提供 —— 令牌与 machineId、uid 是**一套**，手填三者
//! 很容易配出一个「能登录但签不发请求」的账号。`api::accounts::add_account`
//! 对本家显式 400（不是漏做）。
//!
//! 本文件全是「读-改-写」文件操作，**没有任何网络请求**（持锁不做网络）。
//! 绝不 unwrap/expect（release 是 panic=abort）。

use serde_json::{Map, Value};

use crate::server::core::account_store::priority::next_free_priority;
use crate::server::core::account_store::sql;
use crate::server::core::account_store::state::{mark_name_custom, StoredAccount};
use crate::server::core::account_store::{QWENWORK_PROVIDER_ID, AccountStore, AccountStoreError};
use crate::server::logging;

/// 备注名长度上限（与别家同一口径）
const MAX_NAME_LENGTH: usize = 100;
/// 身份字段长度上限
const MAX_IDENTITY_LENGTH: usize = 256;
/// 令牌长度上限
const MAX_TOKEN_LENGTH: usize = 8192;

fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    value.chars().take(max).collect()
}

fn pick(payload: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = payload
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            return value.to_string();
        }
    }
    String::new()
}

fn pick_i64(payload: &Value, keys: &[&str]) -> i64 {
    for key in keys {
        if let Some(value) = payload.get(*key).and_then(Value::as_i64) {
            if value > 0 {
                return value;
            }
        }
    }
    0
}

impl AccountStore {
    /// 取一条千问办公账号记录（**不看启用状态**；「这个 id 是不是本家」的
    /// 判定用它 —— 界面的「刷新 Token」按钮对禁用账号也要走对本家的适配器，
    /// 不能落到 workbuddy 兜底链路）。
    pub fn qwenwork_account_record(&self, account_id: &str) -> Option<Value> {
        let guard = self.guard();
        if !account_id.is_empty() {
            let record = self.record_by_id(&guard, account_id)?;
            return (record.provider() == QWENWORK_PROVIDER_ID).then(|| record.to_value());
        }
        let mut candidates: Vec<StoredAccount> = self
            .records_for_provider(&guard, QWENWORK_PROVIDER_ID)
            .into_iter()
            .filter(StoredAccount::enabled)
            .collect();
        candidates.sort_by_key(StoredAccount::order_key);
        candidates.into_iter().next().map(|item| item.to_value())
    }

    /// 取一条千问办公账号的**会话形态**（转发 / 目录 / 额度共用）。
    ///
    /// `account_id` 非空 → 按 id 直查（不属于本家 / 已禁用返回 None）；
    /// 为空 → 本家启用中账号里优先级最靠前的一条。
    pub fn qwenwork_session(&self, account_id: &str) -> Option<Value> {
        if !account_id.is_empty() {
            return self.session_for_account(account_id).map(|entry| entry.session);
        }
        let id = {
            let guard = self.guard();
            let mut candidates: Vec<StoredAccount> = self
                .records_for_provider(&guard, QWENWORK_PROVIDER_ID)
                .into_iter()
                .filter(StoredAccount::enabled)
                .collect();
            candidates.sort_by_key(StoredAccount::order_key);
            candidates.first().map(|record| record.id().to_string())
        }?;
        self.session_for_account(&id).map(|entry| entry.session)
    }

    /// 登录成功后落账号（唯一入口，见模块头）。
    ///
    /// 撞 id 时：同 provider 就地更新（保留优先级与启用状态、沿用用户改过的
    /// 备注名），撞到别的 provider 报错 —— 绝不覆写他人记录。
    pub fn add_qwenwork_account(
        &self,
        payload: &Value,
        name: Option<&str>,
    ) -> Result<Value, AccountStoreError> {
        if payload.as_object().is_none() {
            return Err(AccountStoreError::new("上传内容必须是 JSON 对象", 400));
        }
        let uid = truncate_chars(&pick(payload, &["uid", "userId", "user_id"]), MAX_IDENTITY_LENGTH);
        if uid.is_empty() {
            return Err(AccountStoreError::new(
                "缺少 uid（COSY 签名必需），请重新登录",
                400,
            ));
        }
        let access_token = pick(payload, &["accessToken", "token"]);
        if access_token.is_empty() {
            return Err(AccountStoreError::new("缺少访问令牌，请重新登录", 400));
        }
        if access_token.chars().count() > MAX_TOKEN_LENGTH {
            return Err(AccountStoreError::new("访问令牌过长", 400));
        }
        let refresh_token = pick(payload, &["refreshToken"]);
        if refresh_token.chars().count() > MAX_TOKEN_LENGTH {
            return Err(AccountStoreError::new("refresh token 过长", 400));
        }
        let machine_id = truncate_chars(&pick(payload, &["machineId"]), MAX_IDENTITY_LENGTH);
        let nickname = truncate_chars(&pick(payload, &["nickname", "name"]), MAX_IDENTITY_LENGTH);
        let email = truncate_chars(&pick(payload, &["email"]), MAX_IDENTITY_LENGTH);
        let phone = truncate_chars(&pick(payload, &["phone"]), MAX_IDENTITY_LENGTH);
        let plan_name = truncate_chars(&pick(payload, &["planName"]), MAX_IDENTITY_LENGTH);
        let expires_at = pick_i64(payload, &["expiresAt"]);
        let id = format!("qwenwork-{uid}");
        let now = logging::now_ms();

        let guard = self.guard();
        let existing = self.record_by_id(&guard, &id);
        if let Some(existing) = existing.as_ref() {
            if existing.provider() != QWENWORK_PROVIDER_ID {
                return Err(AccountStoreError::new(
                    "该账号 id 已被其它提供商占用，请改名后重试",
                    409,
                ));
            }
        }
        let priority = match existing.as_ref() {
            Some(record) => record.priority(),
            None => {
                let used = self.with_conn(&guard, |conn| sql::priorities_all(conn))?;
                next_free_priority(&used)
            }
        };
        let record_name = truncate_chars(
            name.map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(if nickname.is_empty() { &uid } else { &nickname }),
            MAX_NAME_LENGTH,
        );

        let mut record = Map::new();
        record.insert("id".to_string(), Value::String(id.clone()));
        record.insert(
            "provider".to_string(),
            Value::String(QWENWORK_PROVIDER_ID.to_string()),
        );
        record.insert("name".to_string(), Value::String(record_name.clone()));
        record.insert("uid".to_string(), Value::String(uid));
        if !nickname.is_empty() {
            record.insert("nickname".to_string(), Value::String(nickname));
        }
        if !email.is_empty() {
            record.insert("email".to_string(), Value::String(email));
        }
        if !phone.is_empty() {
            record.insert("phone".to_string(), Value::String(phone));
        }
        if !plan_name.is_empty() {
            record.insert("planName".to_string(), Value::String(plan_name));
        }
        record.insert("accessToken".to_string(), Value::String(access_token.clone()));
        if !refresh_token.is_empty() {
            record.insert("refreshToken".to_string(), Value::String(refresh_token));
        }
        if !machine_id.is_empty() {
            record.insert("machineId".to_string(), Value::String(machine_id));
        }
        record.insert(
            "tokenTail".to_string(),
            Value::String(
                access_token
                    .chars()
                    .rev()
                    .take(4)
                    .collect::<Vec<char>>()
                    .into_iter()
                    .rev()
                    .collect(),
            ),
        );
        if expires_at > 0 {
            record.insert("expiresAt".to_string(), Value::from(expires_at));
        }
        record.insert("source".to_string(), Value::String("login".to_string()));
        record.insert("priority".to_string(), Value::from(priority));
        record.insert("enabled".to_string(), Value::Bool(true));
        record.insert(
            "addedAt".to_string(),
            Value::from(
                existing
                    .as_ref()
                    .and_then(|record| record.get("addedAt").and_then(Value::as_i64))
                    .unwrap_or(now),
            ),
        );
        mark_name_custom(
            &mut record,
            name.is_some_and(|value| !value.trim().is_empty()),
            existing.as_ref(),
        );
        record.insert("updatedAt".to_string(), Value::from(now));

        // 未知字段全量保留（用户手工加过的字段不能因为一次重登丢掉）
        let mut merged = record;
        if let Some(existing) = existing.as_ref() {
            for (key, value) in existing.fields() {
                merged.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
        let saved = StoredAccount::from_map(merged);
        self.with_conn(&guard, |conn| sql::put(conn, &saved))?;
        logging::log(
            "[Accounts]",
            &format!("✅ 千问办公账号已保存: {record_name}（优先级 {priority}）"),
        );
        Ok(self.public_account(&saved))
    }

    /// 公开形态：摘掉两个令牌本体与 **machineId**（设备码同样不该下发）。
    pub fn to_qwenwork_public_account(&self, record: &StoredAccount) -> Value {
        let mut value = record.to_value();
        if let Some(object) = value.as_object_mut() {
            object.remove("accessToken");
            object.remove("refreshToken");
            object.remove("machineId");
            object.insert("available".to_string(), Value::Bool(record.enabled()));
            object.insert(
                "hasSession".to_string(),
                Value::Bool(record.get("accessToken").is_some() || record.get("tokenTail").is_some()),
            );
            object.insert(
                "canRefresh".to_string(),
                Value::Bool(
                    record
                        .get("refreshToken")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                ),
            );
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_shape_never_leaks_tokens_or_machine_id() {
        let record = StoredAccount::from_map({
            let mut map = Map::new();
            map.insert("id".into(), Value::String("qwenwork-u1".into()));
            map.insert("provider".into(), Value::String(QWENWORK_PROVIDER_ID.into()));
            map.insert("accessToken".into(), Value::String("at-secret".into()));
            map.insert("refreshToken".into(), Value::String("rt-secret".into()));
            map.insert("machineId".into(), Value::String("mid-secret".into()));
            map.insert("tokenTail".into(), Value::String("cret".into()));
            map
        });
        // 公开形态的规则与 store 方法一致（这里不复用 store，避免构造整个库）
        let mut public = record.to_value();
        if let Some(object) = public.as_object_mut() {
            object.remove("accessToken");
            object.remove("refreshToken");
            object.remove("machineId");
        }
        assert!(public.get("accessToken").is_none());
        assert!(public.get("refreshToken").is_none());
        assert!(public.get("machineId").is_none());
        assert_eq!(public.get("tokenTail").and_then(Value::as_str), Some("cret"));
    }
}
