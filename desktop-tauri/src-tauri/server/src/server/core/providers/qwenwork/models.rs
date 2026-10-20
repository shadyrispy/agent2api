//! 千问办公的模型目录：**签名后的远程清单是权威**，内置三条只作兜底。
//!
//! ── 一个被纠正的结论（2026-10-20）──────────────────────────
//! 参考实现说 `/api/v2/model/list` 会 403，于是早期把它当成「没有可用目录」。
//! 实测那 403 是**没签名**：`{"code":"101","message":"Signature invalid"}`。
//! 用与聊天同一套 COSY 头签一个空 body 的 GET，同一个接口返回 200 与完整目录
//! （`qwork` 段 3 条，另有 chat/developer/assistant/... 若干空段）。
//! 所以本文件照 `qoder/models.rs` 的做法：GET 也签名（`cosy::build_api_headers`）。
//!
//! ── 目录里有什么（实测）────────────────────────────────────
//! ```text
//!   key            display_name   is_vl  is_reasoning  max_input_tokens  price_factor
//!   flash          标准           true   true          1000000           0.1
//!   pro            高级           true   true          1000000           1
//!   qwen3.8-max-preview  Qwen3.8-Max true true        1000000           1.8
//!   context_config: 200K / 400K / 1M（1M 是默认档）
//! ```
//! 三条都**收图**（`is_vl: true`，端到端实测见 `envelope.rs` 的模块头），
//! 都只推理；`price_factor` 就是倍率列要显示的读数。
//!
//! ── 拉不到时怎么办 ─────────────────────────────────────────
//! 内置表是**协议事实**（上游 key 就这三个），不是猜测；签名失败 / 网络失败 /
//! 结构漂移都保留内置表，只记日志。远程成功时以远程为准（上游下架某个 key
//! 就不再广告它），并带 `mtime` 进落盘缓存 —— 重启后仍读得回来
//! （`catalog_cache::ALL_SCOPES` 已登记）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Map, Value};

use crate::server::core::providers::adapter::ModelRefreshOutcome;
use crate::server::core::providers::catalog_cache;
use crate::server::logging;

use super::constants;
use super::cosy::{self, QwenworkIdentity};
use super::credentials::QwenworkCredentials;

/// 落盘缓存的槽位
pub const SCOPE: &str = catalog_cache::SCOPE_QWENWORK;

/// 远程目录的 TTL（与别家同一量级：六小时一次足够）
const CATALOG_TTL_MS: i64 = 6 * 3600 * 1000;

/// 目录里的一条模型
#[derive(Clone, Debug)]
struct Entry {
    /// 上游 key（`pro` / `flash` / …）
    key: String,
    /// 展示名（上游 `i18n.display_name.zh`，缺省回落 `display_name`）
    display: String,
    max_input: i64,
    /// `is_vl`：能不能收图
    vl: bool,
    reasoning: bool,
    /// 相对 pro 的倍率（`price_factor`）；缺省 = 不广告（界面显示 —）
    price: Option<f64>,
    /// `enable`（上游关掉的模型不广告）
    enabled: bool,
    /// 上游的默认模型标记（目前只用于日志）
    is_default: bool,
}

#[derive(Clone, Default)]
struct CatalogState {
    entries: Vec<Entry>,
    fetched_at: i64,
}

static STATE: OnceLock<Mutex<Option<CatalogState>>> = OnceLock::new();

fn state() -> &'static Mutex<Option<CatalogState>> {
    STATE.get_or_init(|| Mutex::new(None))
}

fn with_state<R>(f: impl FnOnce(&mut Option<CatalogState>) -> R) -> R {
    let mut guard = match state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.is_none() {
        if let Some(cached) = catalog_cache::load(SCOPE) {
            let entries: Vec<Entry> = cached
                .models
                .iter()
                .filter_map(entry_from_cached)
                .collect();
            if !entries.is_empty() {
                *guard = Some(CatalogState {
                    entries,
                    fetched_at: cached.fetched_at,
                });
            }
        }
    }
    f(&mut guard)
}

/// 内置兜底（协议事实；远程拉到后以远程为准）
fn fallback_entries() -> Vec<Entry> {
    constants::MODELS
        .iter()
        .map(|spec| Entry {
            key: spec.upstream.to_string(),
            display: spec.label.to_string(),
            max_input: constants::MAX_INPUT_TOKENS,
            // 目录声明三条都 `is_vl: true`，且端到端实测通过（见模块头）
            vl: true,
            reasoning: true,
            price: Some(spec.price_factor),
            enabled: true,
            is_default: spec.id == constants::DEFAULT_MODEL,
        })
        .collect()
}

/// 当前对外目录
pub fn list() -> Vec<Value> {
    let entries = with_state(|guard| {
        guard
            .as_ref()
            .map(|state| state.entries.clone())
            .unwrap_or_default()
    });
    let entries = if entries.is_empty() {
        fallback_entries()
    } else {
        entries
    };
    entries
        .iter()
        .filter(|entry| entry.enabled)
        .map(to_manifest_value)
        .collect()
}

/// 远程目录是否拉到过
pub fn remote_refreshed() -> bool {
    with_state(|guard| {
        guard
            .as_ref()
            .map(|state| state.fetched_at > 0 && !state.entries.is_empty())
            .unwrap_or(false)
    })
}

/// 远程目录最后一次落地时刻（毫秒；0 = 没有）
pub fn last_refreshed_at() -> i64 {
    with_state(|guard| guard.as_ref().map(|state| state.fetched_at).unwrap_or(0))
}

fn age_ms() -> i64 {
    with_state(|guard| {
        guard
            .as_ref()
            .map(|state| logging::now_ms() - state.fetched_at)
            .unwrap_or(0)
    })
}

/// 刷新目录：签名 GET，成功即权威；失败保留现有清单并如实汇报。
pub async fn refresh(credentials: &QwenworkCredentials, force: bool) -> ModelRefreshOutcome {
    if !force && remote_refreshed() && age_ms() < CATALOG_TTL_MS {
        return ModelRefreshOutcome::unchanged();
    }
    let url = format!("{}{}", constants::GATEWAY, constants::MODELS_PATH);
    let identity = QwenworkIdentity {
        uid: &credentials.uid,
        token: &credentials.access_token,
        machine_id: &credentials.machine_id,
    };
    // GET 也要签名（见模块头：裸 Bearer 是 403 Signature invalid）
    let headers = match cosy::build_api_headers(&url, &identity) {
        Ok(headers) => headers,
        Err(error) => return ModelRefreshOutcome::failed(error.message),
    };
    let response = match crate::server::core::auth_http::send_raw(
        "GET",
        &url,
        None,
        &headers,
        None,
        Some(20_000),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            return ModelRefreshOutcome::failed(format!("千问办公目录请求失败: {error}"));
        }
    };
    if !(200..300).contains(&response.status) {
        logging::log(
            "[QwenWork]",
            &format!(
                "目录请求失败（HTTP {}），继续使用内置三条清单",
                response.status
            ),
        );
        return ModelRefreshOutcome::unchanged();
    }
    let payload = response.payload.unwrap_or(Value::Null);
    let entries = parse_catalog(&payload);
    if entries.is_empty() {
        logging::log(
            "[QwenWork]",
            "目录响应里没有 qwork 模型（结构漂移？），保留内置三条清单",
        );
        return ModelRefreshOutcome::unchanged();
    }
    let fetched_at = logging::now_ms();
    let cached: Vec<Value> = entries.iter().map(to_cached_value).collect();
    catalog_cache::save(SCOPE, &cached, fetched_at);
    let count = entries.len();
    with_state(|guard| {
        *guard = Some(CatalogState { entries, fetched_at });
    });
    logging::log("[QwenWork]", &format!("目录刷新完成：{count} 个模型（远程）"));
    ModelRefreshOutcome::refreshed(count)
}

/// 从目录响应里抽 `qwork` 段
fn parse_catalog(payload: &Value) -> Vec<Entry> {
    let Some(items) = payload.get("qwork").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let key = object
            .get("key")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        if key.is_empty() {
            continue;
        }
        let enabled = object.get("enable").and_then(Value::as_bool).unwrap_or(true);
        let display = object
            .get("i18n")
            .and_then(|i18n| i18n.get("display_name"))
            .and_then(|names| names.get("zh"))
            .and_then(Value::as_str)
            .or_else(|| object.get("display_name").and_then(Value::as_str))
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        entries.push(Entry {
            display: if display.is_empty() { key.clone() } else { display },
            key,
            max_input: object
                .get("max_input_tokens")
                .and_then(Value::as_i64)
                .filter(|value| *value > 0)
                .unwrap_or(constants::MAX_INPUT_TOKENS),
            vl: object.get("is_vl").and_then(Value::as_bool).unwrap_or(false),
            reasoning: object
                .get("is_reasoning")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            price: object
                .get("price_factor")
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite()),
            enabled,
            is_default: object
                .get("is_default")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }
    entries
}

/// 一条模型 → 聚合层认的条目形态（键名对照 `core/models/shape.rs::list_item`）
fn to_manifest_value(entry: &Entry) -> Value {
    let mut object = Map::new();
    object.insert(
        "id".to_string(),
        Value::String(format!("qwen/{}", entry.key)),
    );
    object.insert("name".to_string(), Value::String(entry.display.clone()));
    object.insert("maxInputTokens".to_string(), Value::from(entry.max_input));
    object.insert("supportsImages".to_string(), Value::Bool(entry.vl));
    object.insert("supportsVideo".to_string(), Value::Bool(false));
    object.insert(
        "supportsReasoning".to_string(),
        Value::Bool(entry.reasoning),
    );
    // OpenAI 形状的工具原样上行（只过滤非 function 的工具）
    object.insert("supportsToolCall".to_string(), Value::Bool(true));
    if let Some(price) = entry.price {
        object.insert("credits".to_string(), Value::String(credits_label(price)));
    }
    Value::Object(object)
}

/// 倍率展示串（本仓的「倍率」列读它；`0` 意思是免费）
fn credits_label(price: f64) -> String {
    if price == 0.0 {
        return "免费".to_string();
    }
    let mut text = format!("{price}");
    if text.contains('.') {
        while text.ends_with('0') {
            text.pop();
        }
        if text.ends_with('.') {
            text.pop();
        }
    }
    format!("x{text}")
}

fn to_cached_value(entry: &Entry) -> Value {
    json!({
        "model": entry.key,
        "name": entry.display,
        "maxInputTokens": entry.max_input,
        "supportsImages": entry.vl,
        "supportsReasoning": entry.reasoning,
        "priceFactor": entry.price,
        "enabled": entry.enabled,
        "isDefault": entry.is_default,
    })
}

fn entry_from_cached(value: &Value) -> Option<Entry> {
    let key = value.get("model").and_then(Value::as_str)?.trim().to_string();
    if key.is_empty() {
        return None;
    }
    Some(Entry {
        key: key.clone(),
        display: value
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .unwrap_or(&key)
            .to_string(),
        max_input: value
            .get("maxInputTokens")
            .and_then(Value::as_i64)
            .filter(|number| *number > 0)
            .unwrap_or(constants::MAX_INPUT_TOKENS),
        vl: value.get("supportsImages").and_then(Value::as_bool).unwrap_or(false),
        reasoning: value
            .get("supportsReasoning")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        price: value
            .get("priceFactor")
            .and_then(Value::as_f64)
            .filter(|number| number.is_finite()),
        enabled: value.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        is_default: value
            .get("isDefault")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内置兜底：三条、都收图、都推理、价格从目录事实来。
    #[test]
    fn fallback_list_matches_the_catalog_facts() {
        let models = list();
        assert_eq!(models.len(), 3);
        let flash = models
            .iter()
            .find(|model| model["id"] == "qwen/flash")
            .expect("flash");
        assert_eq!(flash["name"], "标准");
        assert_eq!(flash["maxInputTokens"], 1_000_000);
        assert_eq!(flash["supportsImages"], true, "目录 is_vl=true，端到端实测过");
        assert_eq!(flash["supportsToolCall"], true);
        assert_eq!(flash["credits"], "x0.1");
        let pro = models
            .iter()
            .find(|model| model["id"] == "qwen/pro")
            .expect("pro");
        assert_eq!(pro["credits"], "x1");
    }

    /// 目录解析：`qwork` 段 + i18n 中文名 + 倍率 + `enable:false` 过滤在 list 层
    #[test]
    fn parse_catalog_reads_the_qwork_section() {
        let entries = parse_catalog(&json!({
            "chat": [],
            "qwork": [
                {
                    "key": "flash",
                    "display_name": "标准",
                    "i18n": { "display_name": { "zh": "标准", "en": "Standard" } },
                    "is_vl": true,
                    "is_reasoning": true,
                    "max_input_tokens": 1000000,
                    "price_factor": 0.1,
                    "enable": true
                },
                {
                    "key": "retired",
                    "display_name": "下架了",
                    "enable": false,
                    "price_factor": 1
                }
            ]
        }));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "flash");
        assert_eq!(entries[0].display, "标准");
        assert_eq!(entries[0].price, Some(0.1));
        assert!(entries[0].vl);
        assert!(!entries[1].enabled);
    }

    #[test]
    fn credits_label_formats_like_the_other_providers() {
        assert_eq!(credits_label(0.0), "免费");
        assert_eq!(credits_label(0.1), "x0.1");
        assert_eq!(credits_label(1.0), "x1");
        assert_eq!(credits_label(1.8), "x1.8");
    }
}
