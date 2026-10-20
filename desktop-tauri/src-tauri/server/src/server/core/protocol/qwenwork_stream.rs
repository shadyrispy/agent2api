//! 千问办公（QwenWork）的 **COSY 信封 SSE** → 标准 chat SSE。
//!
//! ── 上游长什么样（参考实现 `qwenwork/chat.js` 的实测注释）────────
//! 外层**永远 HTTP 200**，真实状态在信封的 `statusCodeValue` 里；每一行是
//! `data:{"statusCodeValue":200,"body":"<内层 OpenAI chunk 的 JSON 字符串>"}`
//! （早期版本可能不带 `data:` 前缀，参考实现两种都认）。流里**没有**
//! `data: [DONE]` —— 上游用 `event:finish` 加一帧统计收尾。
//!
//! ── 这台状态机要解决的三件事（每一件都对应一种静默失败）────────
//!   1. **不剥信封** → 把 503 当 200 透传，客户端永远看不出失败；
//!   2. **不逐行剥 `data:` 前缀** → 整段 JSON 解析必然失败、异常被吞成 null，
//!      于是**所有信封错误静默成功**（参考实现自己踩过：`chat.js:250-257`）；
//!   3. **不补收尾** → 上游不发 `[DONE]`，不补的话下游一直等结束标记，
//!      表现为「流挂住不返回」。
//!
//! ── 与另外几台翻译机的关系 ──────────────────────────────────
//! 壳（`upstream::translate::QwenworkToChatStream`）与 Anthropic / Command Code /
//! Gemini / 智谱四台逐行同构：`响应字节 → 空闲守卫 → 状态机 → 帧队列`，
//! 错误在构造时折进 `io::Error`，EOF 时调 `finish()` 收尾。差别只在状态机
//! 认的事件词表与"何时算完成"。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use serde_json::{json, Value};

use bytes::Bytes;

use super::{chat_frame, string_value};

/// 一行原始 SSE（含 `event:` 行 —— 收尾信号在它上面）
struct LineBuffer {
    tail: Vec<u8>,
}

impl LineBuffer {
    fn new() -> Self {
        Self { tail: Vec::new() }
    }

    fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        self.tail.extend_from_slice(chunk);
        let mut start = 0usize;
        while let Some(offset) = self.tail[start..].iter().position(|byte| *byte == b'\n') {
            let end = start + offset;
            let line = String::from_utf8_lossy(&self.tail[start..end]).to_string();
            out.push(line);
            start = end + 1;
        }
        self.tail.drain(..start);
        out
    }

    fn finish(&mut self) -> Vec<String> {
        if self.tail.is_empty() {
            return Vec::new();
        }
        let line = String::from_utf8_lossy(&self.tail).to_string();
        self.tail.clear();
        vec![line]
    }
}

/// 上游信封 SSE → chat SSE 的状态机
pub struct ChatFromQwenworkStream {
    buffer: LineBuffer,
    /// 输出帧的 model（上游真名；ForwardStream 的回写层按需改回请求名）
    model: String,
    id: String,
    created: i64,
    /// 已下发过内容帧
    started: bool,
    /// 已收尾（不再吃上游帧）
    finished: bool,
    /// 见过完成信号（`event:finish` / `[DONE]` / 带 finish_reason 的 chunk）
    saw_finish: bool,
    /// 最后一帧里的 finish_reason（缺省 stop）
    finish_reason: Option<String>,
    /// 内层 usage
    usage: Option<Value>,
}

impl ChatFromQwenworkStream {
    pub fn new(model: &str) -> Self {
        Self {
            buffer: LineBuffer::new(),
            model: model.to_string(),
            id: String::new(),
            created: crate::server::logging::now_ms() / 1000,
            started: false,
            finished: false,
            saw_finish: false,
            finish_reason: None,
            usage: None,
        }
    }

    /// 吃一段上游字节，吐出要下发的 chat SSE 帧。
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Bytes> {
        let mut out = Vec::new();
        for line in self.buffer.push(chunk) {
            out.extend(self.consume_line(&line));
            if self.finished {
                break;
            }
        }
        out
    }

    /// 上游流结束：冲刷残留半行，再按「有没有完成信号」收尾。
    pub fn finish(&mut self) -> Vec<Bytes> {
        if self.finished {
            return Vec::new();
        }
        let mut out = Vec::new();
        for line in self.buffer.finish() {
            out.extend(self.consume_line(&line));
            if self.finished {
                return out;
            }
        }
        if !self.saw_finish {
            // 没等到 `event:finish` / `[DONE]` / finish_reason：按「响应被截断」
            // 报错（不补一个假的 stop —— 那会把一次断流记成一次成功回答）
            return self.fail_message(
                "上游流在完成事件之前结束（响应被截断）",
                "upstream_error",
                502,
            );
        }
        self.complete()
    }

    /// 一行 → 零到多帧
    fn consume_line(&mut self, line: &str) -> Vec<Bytes> {
        if self.finished {
            return Vec::new();
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(':') {
            return Vec::new();
        }
        // 事件名：上游用 `event:finish` 收尾（没有 [DONE]）
        if let Some(event) = trimmed.strip_prefix("event:") {
            let event = event.trim();
            if event.eq_ignore_ascii_case("finish") || event.eq_ignore_ascii_case("end") {
                self.saw_finish = true;
            }
            return Vec::new();
        }
        let payload = match trimmed.strip_prefix("data:") {
            Some(rest) => rest.trim(),
            // 容错：早期版本可能不带前缀（参考实现两种都认）
            None => trimmed,
        };
        if payload.is_empty() {
            return Vec::new();
        }
        if payload == "[DONE]" {
            self.saw_finish = true;
            return Vec::new();
        }
        let Ok(outer) = serde_json::from_str::<Value>(payload) else {
            // 非 JSON 行：上游偶尔会夹进度行，忽略但留一条 verbose 日志
            crate::server::logging::verbose("[QwenWork]", "SSE 行不是 JSON，已忽略");
            return Vec::new();
        };
        self.consume_envelope(&outer)
    }

    /// 信封对象 → 零到多帧
    fn consume_envelope(&mut self, outer: &Value) -> Vec<Bytes> {
        // ① 信封级错误：HTTP 恒 200，真实状态在这里
        let status = outer
            .get("statusCodeValue")
            .and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
            })
            .unwrap_or(0);
        if status >= 400 {
            let code = inner_code(outer);
            let message = if code == Some(80411) {
                // 实测：输入 ~987k token + 缺省 max_tokens 32k 超过 1M 时上游给
                // 这个码，文案只有一句泛泛的 "Error in upstream response"。
                // 换成能照着做的说明（上下文是「输入 + 输出」的合计预算）。
                "请求超出千问办公的上下文上限（输入 + max_tokens 合计不能超过 1M；上游 80411）"
                    .to_string()
            } else {
                envelope_message(outer)
            };
            return self.fail_message(&message, "upstream_error", status);
        }

        // ② 内层 chunk：`body` 可能是字符串（常见）或对象
        let inner = match outer.get("body") {
            None => {
                // 有的帧把 chunk 直接放在顶层（参考实现也认这种）
                return self.consume_chunk(outer);
            }
            Some(Value::Null) => return Vec::new(),
            Some(Value::String(text)) => {
                let text = text.trim();
                if text.is_empty() || text == "[DONE]" {
                    return Vec::new();
                }
                match serde_json::from_str::<Value>(text) {
                    Ok(value) => value,
                    Err(_) => {
                        crate::server::logging::verbose(
                            "[QwenWork]",
                            "信封 body 不是 JSON，已忽略",
                        );
                        return Vec::new();
                    }
                }
            }
            Some(value) => value.clone(),
        };
        self.consume_chunk(&inner)
    }

    /// 内层 chunk → chat 帧
    fn consume_chunk(&mut self, chunk: &Value) -> Vec<Bytes> {
        // 内层层面的错误：`{"code":"403","message":"Model is not available for this user"}`
        if let Some(code) = chunk
            .get("code")
            .and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
            })
            .filter(|code| *code >= 400)
        {
            let message = chunk
                .get("message")
                .map(string_value)
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| "上游返回错误".to_string());
            return self.fail_message(&message, "upstream_error", code);
        }

        // 完成事件（有的帧只带 `event:"finish"` 或 `type:"finish"`）
        let event = chunk
            .get("event")
            .or_else(|| chunk.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if event.eq_ignore_ascii_case("finish") || event.eq_ignore_ascii_case("end") {
            self.saw_finish = true;
        }

        // 不是 chat chunk（没有 choices）：可能是统计 / 心跳帧
        let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
            if chunk.get("usage").is_some() {
                self.usage = chunk.get("usage").cloned();
            }
            return Vec::new();
        };

        // 记录 finish_reason / usage
        for choice in choices {
            if let Some(reason) = choice
                .get("finish_reason")
                .and_then(Value::as_str)
                .filter(|reason| !reason.trim().is_empty())
            {
                self.saw_finish = true;
                self.finish_reason = Some(reason.to_string());
            }
        }
        if let Some(usage) = chunk.get("usage").filter(|usage| usage.is_object()) {
            self.usage = Some(usage.clone());
        }

        // ── 上游的「统计帧」不转发 ──────────────────────────────
        // 实测：finish 之后还会来一帧 `choices:[{delta:{},…}]` + `raw_usage`
        // （内含 `model_account` / `provider_model` / `target` / `sub_usages`
        // 等**上游内部路由信息**）。它既没有内容也没有 finish_reason，
        // 转发出去只会让客户端多收一个空 delta，并把上游内部元数据泄漏给下游。
        // usage 已经在上面抄进 `self.usage`，收尾时由本机统一补一帧。
        let stats_only = choices.iter().all(|choice| {
            let no_finish = choice
                .get("finish_reason")
                .map(Value::is_null)
                .unwrap_or(true);
            let empty_delta = choice
                .get("delta")
                .and_then(Value::as_object)
                .map(|delta| delta.is_empty())
                .unwrap_or(true);
            no_finish && empty_delta
        });
        if stats_only && chunk.get("usage").is_some() {
            return Vec::new();
        }

        self.started = true;
        if self.id.is_empty() {
            self.id = chunk
                .get("id")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .unwrap_or("chatcmpl-qwenwork")
                .to_string();
        }

        // 补三个下游会读的字段（上游缺省时）；上游内部元数据一律不转发
        let mut frame = chunk.clone();
        if let Some(object) = frame.as_object_mut() {
            object.remove("raw_usage");
            object.remove("sub_usages");
            object
                .entry("id".to_string())
                .or_insert_with(|| Value::String(self.id.clone()));
            object
                .entry("object".to_string())
                .or_insert_with(|| Value::String("chat.completion.chunk".to_string()));
            object
                .entry("created".to_string())
                .or_insert_with(|| Value::from(self.created));
            let model_missing = object
                .get("model")
                .and_then(Value::as_str)
                .map(|text| text.trim().is_empty())
                .unwrap_or(true);
            if model_missing {
                object.insert("model".to_string(), Value::String(self.model.clone()));
            }
        }
        vec![chat_frame(&frame)]
    }

    /// 正常收尾：finish 帧（缺省 stop）+ usage 帧 + `[DONE]`
    fn complete(&mut self) -> Vec<Bytes> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let reason = self
            .finish_reason
            .clone()
            .unwrap_or_else(|| "stop".to_string());
        let mut out = Vec::new();
        // 下游（聚合器与 ForwardStream）需要一个带 finish_reason 的收尾帧；
        // 上游通常已经给过，没给就补一个空的
        if self.finish_reason.is_none() {
            out.push(chat_frame(&json!({
                "id": self.id,
                "object": "chat.completion.chunk",
                "created": self.created,
                "model": self.model,
                "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }],
            })));
        }
        if let Some(usage) = self.usage.clone() {
            out.push(chat_frame(&json!({
                "id": self.id,
                "object": "chat.completion.chunk",
                "created": self.created,
                "model": self.model,
                "choices": [],
                "usage": usage,
            })));
        }
        out.push(Bytes::from_static(b"data: [DONE]\n\n"));
        out
    }

    /// 失败收尾：错误帧 + `[DONE]`（不补 usage，理由见 CommandCode 那台的说明）
    fn fail_message(&mut self, message: &str, kind: &str, status: i64) -> Vec<Bytes> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let mut error = json!({
            "message": message,
            "type": kind,
            "status": status,
        });
        if status == 429 {
            if let Some(object) = error.as_object_mut() {
                object.insert("retry_after".to_string(), Value::from(30));
            }
        }
        let mut frame = json!({ "error": error });
        if status == 429 {
            if let Some(object) = frame.as_object_mut() {
                object.insert("retry_after".to_string(), Value::from(30));
            }
        }
        vec![chat_frame(&frame), Bytes::from_static(b"data: [DONE]\n\n")]
    }
}

/// 信封 `body` 里的业务码（`{"code":"80411",…}`）；没有就给 None
fn inner_code(outer: &Value) -> Option<i64> {
    let inner = match outer.get("body")? {
        Value::String(text) => serde_json::from_str::<Value>(text).ok()?,
        Value::Object(_) => outer.get("body").cloned()?,
        _ => return None,
    };
    inner
        .get("code")
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|text| text.parse::<i64>().ok()))
        })
}

/// 信封的错误文案：`body` 里的 `message` / `error`，其次是信封自身的 `message`
fn envelope_message(outer: &Value) -> String {
    let from_body = outer.get("body").and_then(|body| match body {
        Value::String(text) => serde_json::from_str::<Value>(text).ok(),
        Value::Object(_) => Some(body.clone()),
        _ => None,
    });
    let message = from_body
        .as_ref()
        .and_then(|inner| {
            inner
                .get("message")
                .or_else(|| inner.get("error"))
                .map(string_value)
        })
        .filter(|text| !text.trim().is_empty())
        .or_else(|| {
            outer
                .get("message")
                .map(string_value)
                .filter(|text| !text.trim().is_empty())
        })
        .unwrap_or_else(|| "千问办公上游返回错误".to_string());
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(frames: &[Bytes]) -> String {
        frames
            .iter()
            .map(|frame| String::from_utf8_lossy(frame).to_string())
            .collect::<String>()
    }

    #[test]
    fn unwraps_envelope_and_emits_plain_chat_frames() {
        let mut machine = ChatFromQwenworkStream::new("pro");
        let chunk = json!({
            "id": "c1",
            "object": "chat.completion.chunk",
            "choices": [{ "index": 0, "delta": { "content": "你好" }, "finish_reason": null }]
        });
        let line = format!(
            "data:{}\n",
            json!({ "statusCodeValue": 200, "body": chunk.to_string() })
        );
        let frames = machine.push(line.as_bytes());
        assert_eq!(frames.len(), 1);
        let body = text(&frames);
        assert!(body.starts_with("data: {"));
        assert!(body.contains("你好"));
        assert!(!body.contains("statusCodeValue"), "信封必须被剥掉");
    }

    #[test]
    fn envelope_status_ge_400_becomes_an_error_frame() {
        let mut machine = ChatFromQwenworkStream::new("pro");
        let line = format!(
            "data:{}\n",
            json!({
                "statusCodeValue": 503,
                "body": "{\"message\":\"Model catalog unavailable\"}"
            })
        );
        let frames = machine.push(line.as_bytes());
        let body = text(&frames);
        assert!(body.contains("\"error\""));
        assert!(body.contains("Model catalog unavailable"));
        assert!(body.contains("[DONE]"));
    }

    #[test]
    fn finish_event_completes_with_done_and_usage() {
        let mut machine = ChatFromQwenworkStream::new("pro");
        let chunk = json!({
            "id": "c1",
            "choices": [{ "index": 0, "delta": { "content": "ok" }, "finish_reason": null }],
            "usage": { "prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4 }
        });
        machine.push(format!("data:{}\n", json!({ "body": chunk.to_string() })).as_bytes());
        machine.push(b"event:finish\n\n");
        let frames = machine.finish();
        let body = text(&frames);
        assert!(body.contains("\"finish_reason\":\"stop\""), "缺省补 stop：{body}");
        assert!(body.contains("\"total_tokens\":4"));
        assert!(body.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn stats_frame_is_dropped_and_internal_metadata_never_forwarded() {
        let mut machine = ChatFromQwenworkStream::new("pro");
        // 实测的统计帧：空 delta + raw_usage（含上游内部路由信息）
        let stats = json!({
            "id": "c1",
            "choices": [{ "delta": {}, "index": 0 }],
            "raw_usage": { "model_account": "maas-x", "provider_model": "glm-5.2", "target": "t1" },
            "sub_usages": [],
            "usage": { "prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4 }
        });
        let frames = machine.push(format!("data:{}\n", json!({ "body": stats.to_string() })).as_bytes());
        assert!(frames.is_empty(), "统计帧不该转发：{:?}", text(&frames));
        machine.push(b"event:finish\n");
        let body = text(&machine.finish());
        assert!(body.contains("\"total_tokens\":4"), "usage 由本机补发");
        assert!(!body.contains("raw_usage"));
        assert!(!body.contains("model_account"));
    }

    /// 80411 = 上下文超限；上游文案泛泛，翻译机换成可执行的说明。
    #[test]
    fn context_overflow_code_gets_an_actionable_message() {
        let mut machine = ChatFromQwenworkStream::new("pro");
        let line = format!(
            "data:{}\n",
            json!({
                "statusCodeValue": 400,
                "statusCode": "Bad Request",
                "body": "{\"code\":\"80411\",\"message\":\"Error in upstream response\"}"
            })
        );
        let body = text(&machine.push(line.as_bytes()));
        assert!(body.contains("上下文上限"), "{body}");
        assert!(body.contains("80411"));
    }

    #[test]
    fn truncated_stream_is_an_error_not_a_silent_success() {
        let mut machine = ChatFromQwenworkStream::new("pro");
        let chunk = json!({
            "id": "c1",
            "choices": [{ "index": 0, "delta": { "content": "半句" }, "finish_reason": null }]
        });
        machine.push(format!("data:{}\n", json!({ "body": chunk.to_string() })).as_bytes());
        let frames = machine.finish();
        let body = text(&frames);
        assert!(body.contains("响应被截断"), "{body}");
        assert!(!body.contains("\"finish_reason\":\"stop\""), "不能补假成功");
    }
}
