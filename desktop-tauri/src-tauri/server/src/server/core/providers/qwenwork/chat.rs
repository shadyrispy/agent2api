//! 千问办公的转发：OpenAI Chat 请求 → COSY 信封 → 签名 → `ChatRequestPlan`。
//!
//! ── 为什么计划里要带「原始字节」──────────────────────────────
//! COSY 签名是对**编码后**的请求体求 MD5（`encode_body` 之后）。
//! 编排层拿到计划后只会 `serde_json::to_string(&plan.body)` —— 那是另一串
//! 字节，签名当场失效。所以这里把编码后的字符串放进
//! [`ChatRequestPlan::raw_body`]，由编排层原样发送（见那字段的说明）。
//!
//! ── 模型名认不出就硬错 ──────────────────────────────────────
//! 上游的模型名只认 `chat_context.extra.modelConfig.key` 与 `model_config.key`；
//! 发错会**静默换模型**（与 Qoder 同一个坑）。因此未知模型名直接 400，
//! 不做「回落到 auto」的兜底。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use axum::http::HeaderMap;
use serde_json::Value;

use crate::server::errors::GatewayError;

use crate::server::core::providers::adapter::ChatRequestPlan;

use super::{constants, cosy, credentials, envelope};

/// 构造一次上游调用。
pub fn build_chat_request(
    account: &Value,
    body: &Value,
    _client_headers: &HeaderMap,
) -> Result<ChatRequestPlan, GatewayError> {
    let credentials = credentials::from_session(account)?;

    let requested = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if requested.is_empty() {
        return Err(GatewayError::with_status(400, "请求缺少 model 字段"));
    }
    let Some(upstream_model) = constants::upstream_key_for(requested) else {
        return Err(GatewayError::with_status(
            400,
            format!(
                "千问办公没有模型「{requested}」（可用：{}）",
                constants::MODELS
                    .iter()
                    .map(|spec| spec.id)
                    .collect::<Vec<&str>>()
                    .join(" / ")
            ),
        ));
    };

    let ids = envelope::EnvelopeIds::fresh()?;
    let payload = envelope::build_body(body, &upstream_model, ids)?;
    // 信封先序列化，再编码：签名覆盖的是编码后的那串字节
    let serialized = serde_json::to_string(&payload).map_err(|error| {
        GatewayError::with_status(500, format!("千问办公请求体序列化失败: {error}"))
    })?;
    let encoded = cosy_encode(&serialized)?;

    let url = format!("{}{}?{}", constants::GATEWAY, constants::CHAT_PATH, constants::CHAT_QUERY);
    let identity = cosy::QwenworkIdentity {
        uid: &credentials.uid,
        token: &credentials.access_token,
        machine_id: &credentials.machine_id,
    };
    let headers = cosy::build_chat_headers(encoded.as_bytes(), &url, &identity, &upstream_model)?;

    // `body` 放**编码前**的信封：调试报文与统计读它更可读；真正发出去的
    // 是 `raw_body`（见模块头）。
    Ok(ChatRequestPlan::signed_chat(url, headers, payload, encoded))
}

/// `encode_body` 的输出是自定义字母表（全 ASCII），转成 String 供原样发送。
fn cosy_encode(serialized: &str) -> Result<String, GatewayError> {
    let bytes = crate::server::core::providers::cosy::encode_body(serialized.as_bytes());
    String::from_utf8(bytes)
        .map_err(|_| GatewayError::with_status(500, "千问办公请求体编码失败（非 ASCII 输出）"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn session() -> Value {
        json!({
            "auth": { "accessToken": "at", "refreshToken": "rt", "expiresAt": 9_999_999_999_999_i64 },
            "account": { "uid": "u1" },
            "machineId": "m1"
        })
    }

    #[test]
    fn plan_carries_signed_bytes_and_envelope() {
        let body = json!({ "model": "qwen/pro", "messages": [{ "role": "user", "content": "hi" }] });
        let plan = build_chat_request(&session(), &body, &HeaderMap::new()).expect("plan");
        assert!(plan.url.starts_with("https://gateway.qwenwork.cn/algo/api/v2/service/pro/sse/agent_chat_generation?"));
        assert!(plan.url.contains("Encode=1"));
        // 计划体是信封（可读），raw_body 是编码后的字节（不可读）
        assert_eq!(plan.body["model_config"]["key"], "pro");
        assert_eq!(plan.body["business"]["product"], "qoder_work");
        let raw = plan.raw_body.as_deref().expect("必须带原始字节");
        assert_ne!(raw, serde_json::to_string(&plan.body).unwrap_or_default());
        assert!(raw.is_ascii());
        assert!(plan
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value.starts_with("Bearer COSY.")));
    }

    /// 认不出的名字（不带 `qwen/` 前缀）仍然硬错 —— 静默回落 auto 是最坏的
    /// 一种「成功」。带前缀的名字按目录权威透传（上游新增模型不用改代码）。
    #[test]
    fn unknown_model_name_is_a_hard_error() {
        let body = json!({ "model": "does-not-exist", "messages": [] });
        let error = build_chat_request(&session(), &body, &HeaderMap::new()).expect_err("必须报错");
        assert_eq!(error.status_code, 400);
        assert!(error.message.contains("没有模型"));
    }

    #[test]
    fn prefixed_model_names_pass_through_to_upstream() {
        let body = json!({ "model": "qwen/future-model", "messages": [] });
        let plan = build_chat_request(&session(), &body, &HeaderMap::new()).expect("目录权威");
        assert_eq!(plan.body["model_config"]["key"], "future-model");
        assert!(plan
            .headers
            .iter()
            .any(|(name, value)| name == "x-model-key" && value == "future-model"));
    }

    #[test]
    fn response_protocol_is_the_envelope_one() {
        let body = json!({ "model": "qwen/flash", "messages": [] });
        let plan = build_chat_request(&session(), &body, &HeaderMap::new()).expect("plan");
        assert_eq!(
            plan.response,
            crate::server::core::providers::adapter::UpstreamResponse::Qwenwork
        );
    }
}
