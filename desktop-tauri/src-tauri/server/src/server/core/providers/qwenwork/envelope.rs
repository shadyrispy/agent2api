//! OpenAI Chat 请求 → 千问办公的 COSY 信封（`agent_chat_generation` 的 body）。
//!
//! 形状照抄参考实现 `qwenwork/chat.js::buildBody`，逐条都有实测支撑：
//!
//! | 字段 | 为什么 |
//! |---|---|
//! | `chat_context.extra.modelConfig.key` 与 `model_config.key` | 模型名**只认这两个位置**，顶层 `model` 不读；只写一处时上游按 auto 走（静默换模型的坑） |
//! | `business` 对象 | 缺了无论签名对不对都 503 `Model catalog unavailable`；它与签名无关，抓到的桌面流量总是带它 |
//! | `messages` 里保留 system | 实测上游只认 messages 里的 system 角色，顶层 `system` 字段不读 —— 摘出去会让系统提示词整体丢失 |
//! | 只留 `type:"function"` 的工具 | Codex 会带 `namespace` / `web_search` 等内置工具，带上去**整轮 400**（不是丢弃该工具），只能静默丢弃非 function 的 |
//! | `tool_choice` 仅在有工具时下发 | 没有工具时带上会被上游拒 |
//! | `stream: true` | 上游只走 SSE，非流式由本网关聚合 |
//! | `imageUrls: null` | 参考实现没有图片上行路径；声明 vision 会骗客户端（见下） |
//!
//! ── 思考档位 ────────────────────────────────────────────────
//! 三个模型都是**仅推理**（`onlyReasoning: true`）：把思考等级关掉（`none`）
//! 会被服务端 400。本网关的信封里 `parameters` 只带温度 / 采样 / 长度四项，
//! `reasoning_effort` **不下发**（等价于默认档），所以不需要改写也不必报错。
//!
//! ── 图片 ────────────────────────────────────────────────────
//! 参考实现不支持图片输入（`is_vl` 标志存在但未实现），本家如实**拒绝**带图
//! 请求（400 明确文案），而不是把图片帧悄悄丢掉 —— 后者会让模型答得头头是道
//! 却完全没看图，是最坏的一种假成功。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use serde_json::{json, Map, Value};

use crate::server::errors::GatewayError;
use crate::server::logging;

use crate::server::core::providers::cosy;

use super::constants;

/// 上游缺省的最大输出（参考实现同款）
const DEFAULT_MAX_TOKENS: i64 = 32_000;

/// 顶层身份 / 会话字段（`request_id` 一族必须每次新生成）
pub struct EnvelopeIds {
    pub request_id: String,
    pub session_id: String,
}

impl EnvelopeIds {
    /// 每次请求全新生成（上游不要求 `session_id` 跨轮保持，参考实现也是现造）
    pub fn fresh() -> Result<Self, GatewayError> {
        Ok(Self {
            request_id: cosy::random_uuid()?,
            session_id: cosy::random_uuid()?,
        })
    }
}

/// 构造信封体。
///
/// `upstream_model` 是上游 key（`pro` / `flash` / `qwen3.8-max-preview`），
/// 由 `chat.rs` 从客户端模型名解析而来 —— 认不出时**已经在上层报错**，
/// 这里不再做兜底（静默降级到 auto 是最坏的一种「成功」）。
pub fn build_body(
    body: &Value,
    upstream_model: &str,
    ids: EnvelopeIds,
) -> Result<Value, GatewayError> {
    let Some(object) = body.as_object() else {
        return Err(GatewayError::with_status(400, "请求体不是 JSON 对象"));
    };
    let messages = match object.get("messages") {
        Some(Value::Array(items)) => items.clone(),
        Some(Value::Null) | None => Vec::new(),
        Some(_) => {
            return Err(GatewayError::with_status(400, "messages 必须是数组"));
        }
    };
    let messages = normalize_messages(messages)?;

    // `text` 取最后一条 user 的正文（参考实现同款：上游用它做 agent 的
    // 「当前输入」，messages 是完整上下文）
    let text = messages
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        .map(|message| {
            message
                .get("content")
                .map(content_text)
                .unwrap_or_default()
        })
        .unwrap_or_default();

    // 系统提示词：顶层仍带一份（兼容），权威来源是 messages 里的 system
    let system = messages
        .iter()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("system"))
        .map(|message| {
            message
                .get("content")
                .map(content_text)
                .unwrap_or_default()
        })
        .unwrap_or_default();

    // 工具：只留标准 OpenAI 形状（`type:"function"` 且带 `function.name`）
    let (tools, dropped) = filter_tools(object.get("tools"));
    if dropped > 0 {
        // 丢弃不是静默的：服务端日志留证据（客户端侧看不到是刻意的 ——
        // 那些工具本来就无法在本通道执行）
        logging::verbose(
            "[QwenWork]",
            &format!("丢弃 {dropped} 个非 function 工具（上游会整轮 400）"),
        );
    }
    let tool_choice = if tools.is_empty() {
        Value::Null
    } else {
        object.get("tool_choice").cloned().unwrap_or(Value::Null)
    };

    let parameters = parameters_of(object);
    let is_vl = upstream_model == "pro" || upstream_model == "flash";

    let mut envelope = Map::new();
    envelope.insert("request_id".to_string(), Value::String(ids.request_id.clone()));
    envelope.insert(
        "request_set_id".to_string(),
        Value::String(ids.request_id.clone()),
    );
    envelope.insert(
        "chat_record_id".to_string(),
        Value::String(ids.request_id),
    );
    envelope.insert("session_id".to_string(), Value::String(ids.session_id));
    envelope.insert("stream".to_string(), Value::Bool(true));
    envelope.insert("chat_task".to_string(), Value::String("FREE_INPUT".to_string()));
    envelope.insert(
        "chat_context".to_string(),
        json!({
            "text": text,
            "features": [],
            "extra": {
                "context": [],
                "modelConfig": { "key": upstream_model, "is_reasoning": false },
                "originalContent": text,
                "chatPrompt": "",
            },
            "chatPrompt": "",
            "imageUrls": null,
        }),
    );
    envelope.insert("is_reply".to_string(), Value::Bool(true));
    envelope.insert("is_retry".to_string(), Value::Bool(false));
    envelope.insert("source".to_string(), Value::from(1));
    envelope.insert("version".to_string(), Value::String("3".to_string()));
    envelope.insert("agent_id".to_string(), Value::String("agent_common".to_string()));
    envelope.insert("task_id".to_string(), Value::String("common".to_string()));
    envelope.insert(
        "session_type".to_string(),
        Value::String("qoder_work".to_string()),
    );
    envelope.insert("aliyun_user_type".to_string(), Value::String(String::new()));
    envelope.insert(
        "model_config".to_string(),
        json!({
            "key": upstream_model,
            "display_name": upstream_model,
            "model": "",
            "format": "openai",
            "is_vl": is_vl,
            "is_reasoning": false,
            "api_key": "",
            "url": "",
            "source": "system",
            "max_input_tokens": constants::MAX_INPUT_TOKENS,
        }),
    );
    envelope.insert(
        "business".to_string(),
        json!({
            "product": constants::BUSINESS_PRODUCT,
            "version": constants::COSY_VERSION,
            "type": constants::BUSINESS_TYPE,
            "id": cosy::random_uuid()?,
            "name": "",
            "begin_at": logging::now_ms(),
            "stage": "processing",
        }),
    );
    envelope.insert("system".to_string(), Value::String(system));
    envelope.insert("messages".to_string(), Value::Array(messages));
    envelope.insert("tools".to_string(), Value::Array(tools));
    if !tool_choice.is_null() {
        envelope.insert("tool_choice".to_string(), tool_choice);
    }
    envelope.insert("parameters".to_string(), parameters);
    Ok(Value::Object(envelope))
}

/// 消息归一：内容数组（OpenAI 多模态形态）只接受纯文本段。
///
/// 带 `image_url` / `input_image` 的直接 400 —— 本通道没有图片上行路径，
/// 悄悄丢掉会让客户端以为模型看过图。
fn normalize_messages(messages: Vec<Value>) -> Result<Vec<Value>, GatewayError> {
    let mut out = Vec::with_capacity(messages.len());
    for message in messages {
        let Some(entry) = message.as_object() else {
            return Err(GatewayError::with_status(400, "messages 的每一项都必须是对象"));
        };
        let content = match entry.get("content") {
            None => Value::Null,
            Some(Value::String(text)) => Value::String(text.clone()),
            Some(Value::Null) => Value::Null,
            Some(Value::Array(parts)) => Value::String(join_text_parts(parts)?),
            Some(other) => Value::String(content_text(other)),
        };
        let mut normalized = entry.clone();
        normalized.insert("content".to_string(), content);
        out.push(Value::Object(normalized));
    }
    Ok(out)
}

/// 文本段拼接；遇到图片段报错（见 [`normalize_messages`]）。
fn join_text_parts(parts: &[Value]) -> Result<String, GatewayError> {
    let mut texts = Vec::new();
    for part in parts {
        match part.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    if !text.is_empty() {
                        texts.push(text.to_string());
                    }
                }
            }
            // 纯字符串段（部分客户端直接给字符串）按文本处理
            None if part.is_string() => {
                if let Some(text) = part.as_str() {
                    texts.push(text.to_string());
                }
            }
            // 图片 / 音频 / 文件：本通道没有上行路径
            _ => {
                return Err(GatewayError::with_status(
                    400,
                    "千问办公通道暂不支持图片 / 音频输入（本家没有已验证的多模态上行路径）",
                ));
            }
        }
    }
    Ok(texts.join("\n"))
}

/// 任意 JSON → 纯文本（字符串原样、数组按文本段拼接、其它序列化）
fn content_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.as_str())
            })
            .collect::<Vec<&str>>()
            .join("\n"),
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// 工具过滤：只留 `{type:"function", function:{name:…}}`。
/// 返回（保留的工具, 丢弃的个数）。
fn filter_tools(value: Option<&Value>) -> (Vec<Value>, usize) {
    let Some(Value::Array(items)) = value else {
        return (Vec::new(), 0);
    };
    let mut kept = Vec::new();
    let mut dropped = 0;
    for item in items {
        let is_function = item.get("type").and_then(Value::as_str) == Some("function")
            && item
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| !name.trim().is_empty());
        if is_function {
            kept.push(item.clone());
        } else {
            dropped += 1;
        }
    }
    (kept, dropped)
}

/// 采样参数：只搬参考实现认的五项；`max_tokens` 缺省给 32000。
fn parameters_of(object: &Map<String, Value>) -> Value {
    let mut parameters = Map::new();
    for key in [
        "temperature",
        "top_p",
        "max_tokens",
        "presence_penalty",
        "frequency_penalty",
    ] {
        if let Some(value) = object.get(key).filter(|value| !value.is_null()) {
            parameters.insert(key.to_string(), value.clone());
        }
    }
    if !parameters.contains_key("max_tokens") {
        parameters.insert("max_tokens".to_string(), Value::from(DEFAULT_MAX_TOKENS));
    }
    Value::Object(parameters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body() -> Value {
        json!({
            "model": "qwen/pro",
            "messages": [
                { "role": "system", "content": "be brief" },
                { "role": "user", "content": "hello" }
            ]
        })
    }

    #[test]
    fn envelope_carries_business_and_both_model_keys() {
        let envelope = build_body(&body(), "pro", EnvelopeIds::fresh().expect("ids")).expect("body");
        assert_eq!(envelope["business"]["product"], "qoder_work");
        assert_eq!(envelope["business"]["stage"], "processing");
        assert_eq!(envelope["chat_context"]["extra"]["modelConfig"]["key"], "pro");
        assert_eq!(envelope["model_config"]["key"], "pro");
        assert_eq!(envelope["model_config"]["max_input_tokens"], 1024000);
        assert_eq!(envelope["stream"], true);
        assert_eq!(envelope["chat_context"]["imageUrls"], Value::Null);
    }

    #[test]
    fn system_message_stays_in_messages() {
        let envelope = build_body(&body(), "pro", EnvelopeIds::fresh().expect("ids")).expect("body");
        let messages = envelope["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(envelope["system"], "be brief");
        assert_eq!(envelope["chat_context"]["text"], "hello");
    }

    #[test]
    fn non_function_tools_are_dropped_and_tool_choice_follows() {
        let mut request = body();
        request["tools"] = json!([
            { "type": "function", "function": { "name": "get_weather", "parameters": {} } },
            { "type": "web_search" }
        ]);
        request["tool_choice"] = json!("auto");
        let envelope = build_body(&request, "pro", EnvelopeIds::fresh().expect("ids")).expect("body");
        assert_eq!(envelope["tools"].as_array().map(Vec::len), Some(1));
        assert_eq!(envelope["tool_choice"], "auto");

        let mut none = body();
        none["tools"] = json!([{ "type": "web_search" }]);
        none["tool_choice"] = json!("auto");
        let envelope = build_body(&none, "pro", EnvelopeIds::fresh().expect("ids")).expect("body");
        assert_eq!(envelope["tools"].as_array().map(Vec::len), Some(0));
        assert!(envelope.get("tool_choice").is_none(), "没有工具就不带 tool_choice");
    }

    #[test]
    fn image_parts_are_rejected_not_silently_dropped() {
        let mut request = body();
        request["messages"] = json!([
            { "role": "user", "content": [
                { "type": "text", "text": "what is this" },
                { "type": "image_url", "image_url": { "url": "data:image/png;base64,AA" } }
            ] }
        ]);
        let error = build_body(&request, "pro", EnvelopeIds::fresh().expect("ids")).expect_err("必须报错");
        assert_eq!(error.status_code, 400);
        assert!(error.message.contains("暂不支持图片"));
    }

    #[test]
    fn defaults_max_tokens_and_drops_reasoning_effort() {
        let mut request = body();
        request["reasoning_effort"] = json!("none");
        let envelope = build_body(&request, "pro", EnvelopeIds::fresh().expect("ids")).expect("body");
        assert_eq!(envelope["parameters"]["max_tokens"], 32000);
        assert!(envelope["parameters"].get("reasoning_effort").is_none());
    }
}
