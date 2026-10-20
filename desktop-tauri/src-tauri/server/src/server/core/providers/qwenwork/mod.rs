//! 千问办公（QwenWork，`gateway.qwenwork.cn`）适配器：账号管理 **加推理转发**。
//!
//! ── 上游长什么样 ────────────────────────────────────────────
//! 与 Qoder 同一套 **COSY 协议栈**（同一个 `client_id`、同一个聊天路径、同一把
//! 服务端公钥、同一套 `Encode=1` 编码），差异只有 `cosyVersion`、客户端身份头
//! 与身份 JSON 的字段集合 —— 所以签名算法只有一份（`providers::cosy`），
//! 本家只提供常量与请求头（`qwenwork::cosy`）。
//!
//! ```text
//!   登录        device flow + PKCE（服务端轮询，本机无回调）
//!   账号信息    GET {gateway}/api/v1/adapter/user/account-context
//!   聊天        POST {gateway}/algo/api/v2/service/pro/sse/agent_chat_generation?Encode=1
//!   换票        POST {gateway}/api/v1/deviceToken/refresh（轮换 refresh token）
//!   目录        GET {gateway}/api/v2/model/list（可能 403 ⇒ 内置三条兜底）
//!   额度        GET https://qwenwork.cn/user/wallets（三池）
//! ```
//!
//! ── 三处与别家不同的取舍（都写在各自模块头）───────────────
//!   1. **签名覆盖编码后的字节**：转发计划必须原样发送 `raw_body`
//!      （`ChatRequestPlan::signed_chat`），让编排层再序列化一次会失效；
//!   2. **响应是 COSY 信封 SSE**（HTTP 恒 200、状态在 `statusCodeValue`、
//!      不发 `[DONE]`）：走 `UpstreamResponse::Qwenwork` 翻译层；
//!   3. **没有签到**：每日额度是自然日自动重置（本家没有签到接口）——
//!      不进 `CHECKIN_PROVIDERS`，也不造假的签到按钮。
//!
//! ── 已知边界（如实写在这里，别当成「已支持」）──────────────────
//! 上游把**业务错误**包在 HTTP 200 的信封里；翻译层会把它们折成 chat 错误帧
//! （流式客户端能看到真实状态，非流式聚合层统一转成 502）。这类「信封里的
//! 401/429」**不会**触发账号轮换或换票 —— 编排层的分类只认 HTTP 状态码，
//! 与 CommandCode 那条翻译通道的现状相同。临期换票由凭证维护链路负责，
//! 令牌失效时客户端会收到明确的 401 文案。
//!
//! ── 浏览器登录：**服务端轮询式**，所以 `supports_web_login` 保持 false ────
//! 授权回调落在网关自己的 `/oauth/callback`，**永远不回到本机**；用户完成授权
//! 后由 `core::login::qwenwork` 轮询取票。把 `supports_web_login` 覆写成 true
//! 会让路由层去等一个永不到达的回调（与 AtomCode / OfficeAce 同一处置）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

pub mod chat;
pub mod constants;
pub mod cosy;
pub mod credentials;
pub mod envelope;
pub mod models;
pub mod oauth;
pub mod usage;

use axum::http::HeaderMap;
use serde_json::Value;

use crate::server::core::account_store::AccountStore;
use crate::server::core::providers::adapter::{
    ChatRequestPlan, ModelRefreshOutcome, ProviderAdapter, UpstreamErrorClass,
};
use crate::server::core::providers::{ProviderKind, refresh_flight};
use crate::server::errors::GatewayError;
use crate::server::logging;

/// 适配器实例
pub struct QwenworkAdapter;

/// 静态单例
pub static QWENWORK_ADAPTER: QwenworkAdapter = QwenworkAdapter;

impl ProviderAdapter for QwenworkAdapter {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Qwenwork
    }

    fn list_models(&self) -> Vec<Value> {
        models::list()
    }

    fn build_chat_request(
        &self,
        account: &Value,
        body: &Value,
        client_headers: &HeaderMap,
    ) -> Result<ChatRequestPlan, GatewayError> {
        chat::build_chat_request(account, body, client_headers)
    }

    /// 错误分类：只有三档在这里有意义。
    ///
    ///   - `401` → `TokenExpired`：refresh token 换一次票再发（本家会轮换，必须写回）；
    ///   - `429` → `QuotaLimited`：额度 / 速率窗口，罚账号冷却并换家；
    ///   - `403` 与其余 → `Fatal`：403 实测是「该模型对这个账号不可用」，
    ///     换账号也是同一面墙（参考实现 `payloadError` 把它归成业务错误）。
    fn classify_error(&self, status: u16, _error_body: &Value) -> UpstreamErrorClass {
        match status {
            401 => UpstreamErrorClass::TokenExpired {
                message: "千问办公令牌已失效（HTTP 401），刷新后重试".to_string(),
            },
            429 => UpstreamErrorClass::QuotaLimited {
                reset_at: None,
                message: "千问办公额度或速率受限（HTTP 429）".to_string(),
                upstream_code: None,
                status,
            },
            _ => UpstreamErrorClass::Fatal {
                status,
                message: format!("千问办公上游返回 {status}"),
                upstream_code: None,
            },
        }
    }

    fn supports_model_refresh(&self) -> bool {
        true
    }

    fn refresh_models<'a>(
        &'a self,
        store: &'a AccountStore,
        account_id: &'a str,
        force: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ModelRefreshOutcome> + Send + 'a>> {
        Box::pin(async move {
            let Some(session) = store.qwenwork_session(account_id) else {
                if account_id.is_empty() {
                    logging::verbose("[Models]", "千问办公模型目录刷新跳过：尚未添加账号");
                    return ModelRefreshOutcome::unchanged();
                }
                return ModelRefreshOutcome::failed("指定的账号不存在或不可用，请重新选择");
            };
            let credentials = match credentials::from_session(&session) {
                Ok(credentials) => credentials,
                Err(error) => return ModelRefreshOutcome::failed(error.message),
            };
            models::refresh(&credentials, force).await
        })
    }

    /// 取访问令牌（**不发网络请求**：转发路径上调，临期只记日志）
    fn ensure_access_token<'a>(
        &'a self,
        store: &'a AccountStore,
        account_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, GatewayError>> + Send + 'a>>
    {
        Box::pin(async move {
            let session = store.qwenwork_session(account_id).ok_or_else(|| {
                GatewayError::with_status(
                    401,
                    if account_id.is_empty() {
                        "还没有可用的千问办公账号（请先添加）".to_string()
                    } else {
                        format!("千问办公账号 {account_id} 不存在或不可用")
                    },
                )
            })?;
            let credentials = credentials::from_session(&session)?;
            if credentials.expiring() {
                logging::verbose(
                    "[QwenWork]",
                    "账号令牌已过期或临期，将按需续期（续期会轮换 refresh token）",
                );
            }
            Ok(credentials.access_token)
        })
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    /// 强制续期：换票 → 把新的一对写回记录（**轮换**，必须单飞）。
    fn refresh_access_token<'a>(
        &'a self,
        store: &'a AccountStore,
        account_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, GatewayError>> + Send + 'a>>
    {
        Box::pin(async move {
            let session = store.qwenwork_session(account_id).ok_or_else(|| {
                GatewayError::with_status(401, "千问办公账号不存在或不可用，请重新登录")
            })?;
            let credentials = credentials::from_session(&session)?;
            if credentials.refresh_token.is_empty() {
                return Err(GatewayError::with_status(
                    401,
                    "千问办公账号没有 refresh_token，无法续期，请重新登录",
                ));
            }
            let key = format!(
                "{}:{}:{}:{}",
                store.file_string(),
                account_id,
                refresh_flight::fingerprint(&credentials.access_token),
                refresh_flight::fingerprint(&credentials.refresh_token),
            );
            match QWENWORK_FLIGHTS.get_or_init(refresh_flight::Table::new).join(&key) {
                refresh_flight::Join::Waiter(waiter) => {
                    waiter.wait().await.map(|bundle| bundle.access_token)
                }
                refresh_flight::Join::Leader(leader) => {
                    let result = refresh_and_save(store, account_id, &credentials).await;
                    leader.finish(result.clone());
                    result.map(|bundle| bundle.access_token)
                }
            }
        })
    }

    fn credentials_expiring(&self, store: &AccountStore, account_id: &str) -> bool {
        if account_id.is_empty() {
            return false;
        }
        store
            .qwenwork_session(account_id)
            .and_then(|session| credentials::from_session(&session).ok())
            .map(|credentials| credentials.expiring())
            .unwrap_or(false)
    }

    fn supports_usage(&self) -> bool {
        true
    }

    /// 回写 `model`：上游回的帧里写的是**它自己的路由名**
    /// （实测 `qwork-openai-chat-mode-pool`），与客户端请求的 `qwen/pro` 不同。
    /// 不覆写这一位，客户端会在每一帧里看到一个陌生的模型名。
    fn sse_model_rewrite(&self) -> bool {
        true
    }

    fn query_usage<'a>(
        &'a self,
        store: &'a AccountStore,
        account_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, GatewayError>> + Send + 'a>>
    {
        Box::pin(async move { usage::query_usage(store, account_id).await })
    }
}

/// 续期单飞表（键含两个令牌指纹：令牌一变就是新的一轮）
static QWENWORK_FLIGHTS: std::sync::OnceLock<refresh_flight::Table<oauth::TokenBundle>> =
    std::sync::OnceLock::new();

async fn refresh_and_save(
    store: &AccountStore,
    account_id: &str,
    credentials: &credentials::QwenworkCredentials,
) -> Result<oauth::TokenBundle, GatewayError> {
    let bundle = oauth::refresh(&credentials.refresh_token).await?;
    let written = store.update_account_tokens(
        account_id,
        Some(&bundle.access_token),
        Some(&bundle.refresh_token),
        (bundle.expires_at > 0).then_some(bundle.expires_at as f64),
        None,
    );
    if !written {
        return Err(GatewayError::with_status(
            502,
            "千问办公续期成功但写回账号失败（账号记录不存在？）：请重新登录",
        ));
    }
    logging::log("[QwenWork]", "令牌已续期并写回账号（refresh token 已轮换）");
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_declares_the_expected_capabilities() {
        let adapter = &QWENWORK_ADAPTER;
        assert_eq!(adapter.kind(), ProviderKind::Qwenwork);
        assert!(adapter.supports_chat(), "COSY 信封转发，能对话");
        assert!(!adapter.is_stateful(), "一次请求 = 一次回答");
        assert!(adapter.supports_model_refresh());
        assert!(adapter.supports_refresh(), "有 deviceToken/refresh");
        assert!(adapter.supports_usage(), "有 wallets 三池");
        // 轮询式登录：不能覆写 web_login（否则路由层去等一个不回本机的回调）
        assert!(!adapter.supports_web_login());
    }
}
