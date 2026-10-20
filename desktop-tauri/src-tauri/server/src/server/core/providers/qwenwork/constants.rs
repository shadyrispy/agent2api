//! 千问办公（QwenWork）的协议常量。
//!
//! 全部实测自参考实现 `dumate2api`（MIT，2026-10-14 直连
//! `gateway.qwenwork.cn` 验证：本地签名 + 19 帧出流）。这些值随官方客户端
//! 版本变化，写在一处便于升级时一处改完（与 `qoder::cosy` 同一处置）。
//!
//! ── 已知的版本敏感项（升级即坏，别当永久真值）────────────────
//!   - `COSY_VERSION` 来自客户端二进制（1.1.0 桌面端实测 1.1.52）
//!   - `CHAT_QUERY` 必须带 `Encode=1`（1.1.0 起要求，缺了 400）
//!   - 请求体必须带 `business` 对象，否则无论签名对不对都 503
//!     `Model catalog unavailable`
//!
//! ── 与 Qoder 的关系 ─────────────────────────────────────────
//! 同一套 COSY 协议栈、同一个 `client_id`、同一个聊天路径、同一把服务端公钥；
//! 差异只有 `COSY_VERSION`、`CLIENT_TYPE`、UA 与几个 `Cosy-Business-*` 头
//! （见 `super::cosy`）。

/// 网关主机
pub const GATEWAY: &str = "https://gateway.qwenwork.cn";
/// 聊天端点（`/algo` 前缀由 [`signature_path`](crate::server::core::providers::cosy::signature_path) 去掉）
pub const CHAT_PATH: &str = "/algo/api/v2/service/pro/sse/agent_chat_generation";
/// 聊天查询串：`Encode=1` 是 1.1.0 起的硬要求
pub const CHAT_QUERY: &str = "FetchKeys=llm_model_result&AgentId=agent_common&Encode=1";
/// 换票（device token refresh）
pub const REFRESH_PATH: &str = "/api/v1/deviceToken/refresh";
/// 模型目录
pub const MODELS_PATH: &str = "/api/v2/model/list";
/// 账号上下文（取 uid / 昵称 / 套餐；wasm 签名要用 uid）
pub const ACCOUNT_CONTEXT_PATH: &str =
    "/api/v1/adapter/user/account-context?include=user,plan,quota,page,data_sharing";
/// 身份明细（真实手机号在 `c_site_user` 里，account-context 只有占位邮箱）
pub const IDENTITIES_PATH: &str = "/api/v1/adapter/auth/identities";

/// 授权页（302 到 qwenwork.cn 的标准 OAuth 授权端点）
pub const DEVICE_SELECT_PATH: &str = "/device/selectAccounts";
/// 取票轮询（**不需要 Authorization**，持有 nonce + verifier 即可）
pub const DEVICE_POLL_PATH: &str = "/api/v1/deviceToken/poll";
/// 官方客户端登记的 client_id（`QWENWORK_CN_CLIENT_ID`）
pub const OAUTH_CLIENT_ID: &str = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb";
/// 回调协议：浏览器最后跳到它（打不开是正常的，结果由服务端记录）
pub const OAUTH_REDIRECT_URI: &str = "qwenwork-cn://";
/// 一次登录的窗口（客户端同款 5 分钟，超时 nonce 就废了）
pub const DEVICE_FLOW_TIMEOUT_MS: u64 = 300_000;
/// 取票轮询间隔（参考实现 1 秒；这里放 2 秒，减少无意义的空轮询）
pub const DEVICE_POLL_INTERVAL_MS: u64 = 2_000;

/// 客户端身份（必须与请求头声明的一致；混用会让 body 与 header 自相矛盾）
pub const IDE_VERSION: &str = "1.1.0";
pub const RELEASE_VERSION: &str = "1.1.0-26091701";
pub const COSY_VERSION: &str = "1.1.52";
pub const CLIENT_TYPE: &str = "6";
pub const BUSINESS_PRODUCT: &str = "qoder_work";
pub const BUSINESS_TYPE: &str = "agent";
pub const SCENE: &str = "qwork";
pub const MACHINE_OS: &str = "x86_64_win32";
pub const LOGIN_VERSION: &str = "v2";
pub const USER_AGENT: &str = "qoderwork/1.1.0";

/// 上下文上限（实测：1250K 汉字 ≈ 1,022,745 token 通过；1262K 起 502，
/// 不是截断而是整轮失败 —— 见参考实现 `chat.js` 的注释）
pub const MAX_INPUT_TOKENS: i64 = 1_024_000;

/// 默认模型（客户端 `auto` 的落点）
pub const DEFAULT_MODEL: &str = "qwen/pro";

/// 对外模型表：`id`（本网关广告名）→ 上游 key。
///
/// 上游只有三个 key，`pro` / `flash` 这种裸名在聚合清单里太容易撞车，
/// 所以对外统一加 `qwen/` 前缀（与参考实现 `dumate2api` 的渠道前缀同一处置）。
/// 三个模型都**只推理**（`onlyReasoning: true`）：`reasoning_effort: none`
/// 会被服务端 400 拒绝 —— 见 `super::chat` 对思考档位的改写。
pub const MODELS: &[ModelSpec] = &[
    ModelSpec {
        id: "qwen/pro",
        upstream: "pro",
        label: "QwenWork Pro",
    },
    ModelSpec {
        id: "qwen/flash",
        upstream: "flash",
        label: "QwenWork Flash",
    },
    ModelSpec {
        id: "qwen/qwen3.8-max-preview",
        upstream: "qwen3.8-max-preview",
        label: "Qwen3.8 Max Preview",
    },
];

/// 一条对外模型
pub struct ModelSpec {
    pub id: &'static str,
    pub upstream: &'static str,
    pub label: &'static str,
}

/// 客户端别名 → 本网关广告名（参考实现三家交叉确认的映射）。
pub const MODEL_ALIASES: &[(&str, &str)] = &[
    ("auto", "qwen/pro"),
    ("qwork-advanced", "qwen/pro"),
    ("qwork-auto", "qwen/pro"),
    ("qwork-lite", "qwen/flash"),
    ("qwen3.8-max", "qwen/qwen3.8-max-preview"),
    ("qmodel_latest", "qwen/qwen3.8-max-preview"),
];

/// 把客户端传来的模型名解析成**上游 key**。
///
/// 接受三种形态：广告名（`qwen/pro`）、裸上游 key（`pro`）、客户端别名
/// （`auto` / `qwork-lite` …）。认不出返回 `None` —— 调用方**必须硬错**
/// （静默换模型是本家与 Qoder 同类的坑：`model_config` 发错会静默降级）。
pub fn upstream_key_for(name: &str) -> Option<&'static str> {
    let name = name.trim();
    if name.is_empty() {
        return Some(MODELS[0].upstream);
    }
    if let Some(spec) = MODELS.iter().find(|spec| spec.id.eq_ignore_ascii_case(name)) {
        return Some(spec.upstream);
    }
    if let Some(spec) = MODELS.iter().find(|spec| spec.upstream.eq_ignore_ascii_case(name)) {
        return Some(spec.upstream);
    }
    MODEL_ALIASES
        .iter()
        .find(|(alias, _)| alias.eq_ignore_ascii_case(name))
        .and_then(|(_, target)| MODELS.iter().find(|spec| spec.id == *target))
        .map(|spec| spec.upstream)
}
