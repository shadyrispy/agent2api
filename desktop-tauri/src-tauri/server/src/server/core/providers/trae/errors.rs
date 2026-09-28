//! Trae 的错误分类与"哪些配置在这条通道上必死"的判定。
//!
//! ── 为什么这一层值得单独成文件 ────────────────────────────
//! Trae 的账号级失败**不体现在 HTTP 状态上**：额度耗尽是 HTTP 200 的 SSE 里
//! 一条 `event: error`（`solosse.go`），而"模型在这条通道不存在"是流内 `4001`。
//! 跨账号降级链的触发条件完全依赖这一层的分类结果 —— 分类错的后果不是报错难听，
//! 而是**给用户一个假成功**（codearts 那边同一条教训），或者把健康账号误冷却 12 小时。
//!
//! 所有判定逐条照参考实现 `plugins/trae/upstream/{client,solosse}.go`，
//! 并由 `vectors/trae-vectors.json` 的 `classify` / `streamErrorKind` /
//! `tooLargeMessage` / `deadModel` 四段钉住（生成器在参考实现包里，
//! 见 `cpa-deploy/trae-vectors/README.md`）。

use serde_json::Value;

/// 错误类别。字符串形态与参考实现 `ErrKind.String()` 逐字一致 ——
/// 对拍报告与日志里两边要能直接对照。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// 成功
    None,
    /// 1005 / 4008：计划或模型配额不足（参考实现硬冷却 12 小时）
    PlanLimit,
    /// 429 / 9074：软限流（60 秒）
    SoftRate,
    /// 401：会话失效（禁用账号）
    SessionDead,
    /// 404：短冷却 60 秒、不累计错误数
    NotFound,
    /// 5xx
    Server,
    /// 其它 4xx
    Client,
    /// 413 或过大文案：请求级问题，**不冷却账号**
    InputTooLarge,
    /// 流内 4001：模型在当前 function 通道不可用，请求级、**不冷却也不累计**
    ModelUnavailable,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PlanLimit => "plan_limit",
            Self::SoftRate => "soft_rate",
            Self::SessionDead => "session_dead",
            Self::NotFound => "not_found",
            Self::Server => "server",
            Self::Client => "client",
            Self::InputTooLarge => "input_too_large",
            Self::ModelUnavailable => "model_unavailable",
        }
    }

    /// 本仓 `UpstreamErrorClass` 的对应档位放在 M4（转发那层）做映射，
    /// 这里刻意**不认识**网关的错误类型 —— 分类知识只写一份。
    pub fn is_request_level(self) -> bool {
        matches!(self, Self::InputTooLarge | Self::ModelUnavailable)
    }
}

/// 「输入过大」的子串词表（大小写不敏感；中文原样匹配）。
///
/// 这条判定的意义不是文案好看，而是**别冷却健康账号**：同一个超大 body
/// 换任何账号都会被拒，把它算成账号错误会连着拖垮整条链。
const INPUT_TOO_LARGE_MARKERS: [&str; 12] = [
    "too long",
    "too many tokens",
    "context length",
    "maximum context",
    "context window",
    "request entity too large",
    "input too large",
    "输入过长",
    "内容过长",
    "上下文过长",
    "上下文长度",
    "超出模型上限",
];

pub fn msg_indicates_input_too_large(message: &str) -> bool {
    let lower = message.to_lowercase();
    INPUT_TOO_LARGE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// 流内业务码里"配额/计划不足"的那几个（与非 2xx 路径共用同一张表，
/// 免得同一个码在两条路径上得到两种语义）。
pub const PLAN_LIMIT_CODES: [i64; 2] = [1005, 4008];

/// 4001 的语义：模型在当前 function 通道不可用。
pub fn is_model_mismatch_code(code: i64) -> bool {
    code == 4001
}

/// 流内 `event: error` 的分类。
///
/// 顺序敏感：`4001` 配 "prompt is too long…" 仍归**过大**（那是输入问题，
/// 不是通道问题），所以过大判定在通道判定之前。
pub fn stream_error_kind(code: i64, message: &str) -> ErrorKind {
    if PLAN_LIMIT_CODES.contains(&code) {
        return ErrorKind::PlanLimit;
    }
    if msg_indicates_input_too_large(message) {
        return ErrorKind::InputTooLarge;
    }
    if is_model_mismatch_code(code) {
        return ErrorKind::ModelUnavailable;
    }
    ErrorKind::Client
}

/// HTTP 状态 + 响应体 → 分类。判定顺序照参考实现 v0.12.51 的注释：
/// 413 提到最顶，避免 body 恰好带 "1005…plan" 字样时被宽松的 plan 匹配
/// 劫持成 12 小时硬冷却。
pub fn classify(status: u16, body: &str) -> ErrorKind {
    let lower = body.to_lowercase();
    if status == 413 {
        return ErrorKind::InputTooLarge;
    }
    if body.contains("\"code\":1005") || (body.contains("1005") && lower.contains("plan")) {
        return ErrorKind::PlanLimit;
    }
    if body.contains("\"code\":4008") {
        return ErrorKind::PlanLimit;
    }
    if (400..500).contains(&status) && msg_indicates_input_too_large(body) {
        return ErrorKind::InputTooLarge;
    }
    if status == 401 {
        // 参考实现这里遍历了一批"会话失效"文案标记，但无论命不命中都返回
        // 同一个类别 —— 那个循环是空转的，这里直接给结论。
        return ErrorKind::SessionDead;
    }
    if status == 429 {
        return ErrorKind::SoftRate;
    }
    if status == 404 {
        return ErrorKind::NotFound;
    }
    if status >= 500 {
        return ErrorKind::Server;
    }
    // 通道不可用放在账号级状态（401/429/404）之后兜底：鉴权失败永远优先按会话失效处理。
    if (400..500).contains(&status) && body.contains("\"code\":4001") {
        return ErrorKind::ModelUnavailable;
    }
    if status >= 400 {
        return ErrorKind::Client;
    }
    ErrorKind::None
}

/// 只由 `solo_agent` / `llm_raw_chat` 那条通道服务的配置名（小写）。
///
/// 这些 config 在 `solo_work_lite` 通道**必定**流内 4001：过滤比"注册出来
/// 再让用户撞上"好，但名单必须是**精确名字**——参考实现原本用前缀匹配
/// （`agnes`、`deepseek-v4`），把实测可用的 `DeepSeek-V4-Flash-Official`
/// 一起误杀过（issue #10），所以这里连"近似名字"都不许加。
const SOLO_AGENT_ONLY_DEAD_NAMES: [&str; 4] = [
    "agnes-2.0-flash",
    "agnes-agent-x",
    "deepseek-v4-flash",
    "deepseek-v4-pro",
];

pub fn config_is_solo_agent_only(config_name: &str) -> bool {
    let lowered = config_name.to_lowercase();
    SOLO_AGENT_ONLY_DEAD_NAMES
        .iter()
        .any(|dead| *dead == lowered)
}

/// 从一条 `event: error` 的 data 里取码与文案（`code` 是 JSON 数字、
/// `message` 是字符串 —— 参考实现只认 `message`，写成 `msg` 会被静默读空）。
pub fn error_event_fields(data: &Value) -> (i64, String) {
    let code = data
        .get("code")
        .and_then(Value::as_f64)
        .map(|value| value as i64)
        .unwrap_or(0);
    let message = data
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    (code, message)
}

#[cfg(test)]
mod tests {
    //! 每一条断言都读同一份向量文件 —— 测试不是"我记得的规则"的回声，
    //! 而是参考实现算出来的答案。
    use super::*;

    const VECTORS: &str = include_str!("vectors/trae-vectors.json");

    fn document() -> Value {
        serde_json::from_str(VECTORS).expect("向量文件必须是合法 JSON")
    }

    #[test]
    fn classify_matches_the_reference_implementation() {
        let document = document();
        let cases = document["classify"].as_array().expect("classify 段是数组");
        assert!(!cases.is_empty());
        for case in cases {
            let status = case["status"].as_u64().expect("status 是数字") as u16;
            let body = case["body"].as_str().expect("body 是字符串");
            let want = case["kind"].as_str().unwrap();
            let got = classify(status, body);
            assert_eq!(want, got.as_str(), "status={status} body={body}");
        }
    }

    #[test]
    fn stream_error_codes_match_the_reference_implementation() {
        let document = document();
        let cases = document["streamErrorKind"].as_array().expect("段存在");
        for case in cases {
            let code = case["code"].as_i64().expect("code 是整数");
            let message = case["msg"].as_str().unwrap();
            assert_eq!(
                case["kind"].as_str().unwrap(),
                stream_error_kind(code, message).as_str(),
                "code={code} msg={message}"
            );
        }
    }

    #[test]
    fn too_large_markers_match_the_reference_implementation() {
        for case in document()["tooLargeMessage"].as_array().expect("段存在") {
            let message = case["msg"].as_str().unwrap();
            assert_eq!(
                case["tooLarge"].as_bool().unwrap(),
                msg_indicates_input_too_large(message),
                "msg={message:?}"
            );
        }
    }

    #[test]
    fn the_dead_list_is_exact_and_case_insensitive() {
        for case in document()["deadModel"].as_array().expect("段存在") {
            let name = case["configName"].as_str().unwrap();
            assert_eq!(
                case["soloAgentOnly"].as_bool().unwrap(),
                config_is_solo_agent_only(name),
                "config={name}"
            );
        }
        // 反向用例（参考实现 issue #10 的教训）：**近似名字绝不能算死**。
        assert!(!config_is_solo_agent_only("deepseek-v4-flash-official"));
        assert!(!config_is_solo_agent_only("deepseek-v4-pro-latest"));
        assert!(!config_is_solo_agent_only("agnes-3.0"));
        // 大小写两种写法都要认（目录里同时出现过）。
        assert!(config_is_solo_agent_only("DeepSeek-V4-Flash"));
        assert!(config_is_solo_agent_only("AGNES-2.0-FLASH"));
    }

    #[test]
    fn the_error_event_reads_message_not_msg() {
        // 参考实现只认 `message`；写成 `msg` 会读出一个空文案 ——
        // 那样 4001 的"过大"判定就永远失效，所以这条单独钉住。
        let (code, message) = error_event_fields(&serde_json::json!({"code": 4008, "message": "quota"}));
        assert_eq!(4008, code);
        assert_eq!("quota", message);
        let (code, message) = error_event_fields(&serde_json::json!({"code": 1005, "msg": "plan limit"}));
        assert_eq!(1005, code);
        assert!(message.is_empty(), "msg 键读不出来是**预期行为**，向量里也是这么记的");
    }

    #[test]
    fn request_level_kinds_are_the_ones_that_must_not_cool_an_account() {
        assert!(ErrorKind::InputTooLarge.is_request_level());
        assert!(ErrorKind::ModelUnavailable.is_request_level());
        assert!(!ErrorKind::PlanLimit.is_request_level(), "配额不足是账号状态，要冷却");
        assert!(!ErrorKind::SessionDead.is_request_level());
    }
}
