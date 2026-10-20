//! 千问办公的模型目录：内置三条 + 远程清单（`GET /api/v2/model/list`）。
//!
//! ── 为什么要有内置清单 ──────────────────────────────────────
//! 上游的目录接口**会 403**（参考实现实测，见 `dumate2api:src/model-info.js`），
//! 而三个模型 key 是协议事实（`pro` / `flash` / `qwen3.8-max-preview`，三家
//! 独立实现交叉确认）。所以内置表是**兜底**，不是「猜」：它是当前协议能发出去
//! 的全部模型。
//!
//! ── 远程清单怎么用 ──────────────────────────────────────────
//! 拉到就按它**取交集**（只保留我们认得的 key）：上游若删掉某个 key，目录里
//! 就不再广告它 —— 避免「点了必 400」。若拉到的条目一个都认不得（结构漂移），
//! **保留内置表**并记日志，而不是把目录清空。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Map, Value};

use crate::server::core::auth_http::send_raw;
use crate::server::core::providers::adapter::ModelRefreshOutcome;
use crate::server::core::providers::catalog_cache;
use crate::server::logging;

use super::constants;
use super::credentials::QwenworkCredentials;

/// 落盘缓存的槽位（与 `catalog_cache::ALL_SCOPES` 同一份登记）
pub const SCOPE: &str = catalog_cache::SCOPE_QWENWORK;

/// 远程目录的 TTL（与别家同一量级：一天一次足够）
const CATALOG_TTL_MS: i64 = 6 * 3600 * 1000;

/// 进程内状态（只装「远程成功拉到的」清单）
#[derive(Clone, Default)]
struct CatalogState {
    /// 远程给出的上游 key 集合（已过滤成我们认得的那些）
    keys: Vec<String>,
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
            let keys: Vec<String> = cached
                .models
                .iter()
                .filter_map(|entry| entry.get("model").and_then(Value::as_str))
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(str::to_string)
                .collect();
            if !keys.is_empty() {
                *guard = Some(CatalogState {
                    keys,
                    fetched_at: cached.fetched_at,
                });
            }
        }
    }
    f(&mut guard)
}

/// 当前对外目录
pub fn list() -> Vec<Value> {
    let remote_keys = with_state(|guard| {
        guard
            .as_ref()
            .map(|state| state.keys.clone())
            .unwrap_or_default()
    });
    constants::MODELS
        .iter()
        .filter(|spec| remote_keys.is_empty() || remote_keys.iter().any(|key| key == spec.upstream))
        .map(|spec| {
            let mut object = Map::new();
            object.insert("id".to_string(), Value::String(spec.id.to_string()));
            object.insert("name".to_string(), Value::String(spec.label.to_string()));
            object.insert(
                "maxInputTokens".to_string(),
                Value::from(constants::MAX_INPUT_TOKENS),
            );
            // 三个模型都只推理（`onlyReasoning: true`）：思考档位关不掉
            object.insert("supportsReasoning".to_string(), Value::Bool(true));
            // OpenAI 形状的工具原样上行（只过滤非 function 的工具）
            object.insert("supportsToolCall".to_string(), Value::Bool(true));
            // 图片：参考实现没有上行路径，未验证 ⇒ 不声称支持
            object.insert("supportsImages".to_string(), Value::Bool(false));
            object.insert("supportsVideo".to_string(), Value::Bool(false));
            // 费率上游不公开（参考实现也没有），不写 `credits` —— 界面显示「—」
            Value::Object(object)
        })
        .collect()
}

/// 远程目录是否拉到过
pub fn remote_refreshed() -> bool {
    with_state(|guard| {
        guard
            .as_ref()
            .map(|state| state.fetched_at > 0 && !state.keys.is_empty())
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

/// 刷新远程目录。
pub async fn refresh(credentials: &QwenworkCredentials, force: bool) -> ModelRefreshOutcome {
    if !force && remote_refreshed() && age_ms() < CATALOG_TTL_MS {
        return ModelRefreshOutcome::unchanged();
    }
    let url = format!("{}{}", constants::GATEWAY, constants::MODELS_PATH);
    let headers = vec![
        ("User-Agent".to_string(), constants::USER_AGENT.to_string()),
        (
            "Authorization".to_string(),
            format!("Bearer {}", credentials.access_token),
        ),
    ];
    let response = match send_raw("GET", &url, None, &headers, None, Some(20_000)).await {
        Ok(response) => response,
        Err(error) => {
            return ModelRefreshOutcome::failed(format!("千问办公目录请求失败: {error}"));
        }
    };
    if response.status == 403 {
        // 参考实现实测的稳定形态：目录接口对代理不可用 ⇒ 内置表就是权威
        logging::verbose("[QwenWork]", "目录接口 403，继续使用内置三条清单");
        return ModelRefreshOutcome::unchanged();
    }
    if !(200..300).contains(&response.status) {
        return ModelRefreshOutcome::failed(format!(
            "千问办公目录请求失败（HTTP {}）",
            response.status
        ));
    }
    let payload = response.payload.unwrap_or(Value::Null);
    let keys = extract_keys(&payload);
    if keys.is_empty() {
        logging::log(
            "[QwenWork]",
            "目录接口返回了认不得的结构，保留内置三条清单（请对照参考实现更新解析）",
        );
        return ModelRefreshOutcome::unchanged();
    }
    let fetched_at = logging::now_ms();
    let cached: Vec<Value> = keys
        .iter()
        .map(|key| json!({ "model": key }))
        .collect();
    catalog_cache::save(SCOPE, &cached, fetched_at);
    let count = keys.len();
    with_state(|guard| {
        *guard = Some(CatalogState { keys, fetched_at });
    });
    logging::log("[QwenWork]", &format!("目录刷新完成：{count} 个模型"));
    ModelRefreshOutcome::refreshed(count)
}

/// 从目录响应里抽上游 key（宽容多种形状），只保留我们认得的。
fn extract_keys(payload: &Value) -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();
    let mut collect = |value: &Value| {
        if let Value::Array(items) = value {
            for item in items {
                let key = match item {
                    Value::String(text) => text.trim().to_string(),
                    Value::Object(object) => ["key", "model", "id", "name"]
                        .iter()
                        .find_map(|field| object.get(*field).and_then(Value::as_str))
                        .map(str::trim)
                        .unwrap_or("")
                        .to_string(),
                    _ => String::new(),
                };
                if !key.is_empty() {
                    raw.push(key);
                }
            }
        }
    };
    collect(payload);
    if let Some(data) = payload.get("data") {
        collect(data);
        if let Some(models) = data.get("models") {
            collect(models);
        }
        if let Some(list) = data.get("list") {
            collect(list);
        }
    }
    if let Some(models) = payload.get("models") {
        collect(models);
    }
    let mut keys: Vec<String> = Vec::new();
    for key in raw {
        // 可能是 `qwen/pro` 这种带前缀的广告名，也可能是裸 key
        let upstream = constants::upstream_key_for(&key).unwrap_or("");
        if !upstream.is_empty() && !keys.iter().any(|existing| existing == upstream) {
            keys.push(upstream.to_string());
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_list_has_three_models_with_honest_capabilities() {
        let models = list();
        assert_eq!(models.len(), 3);
        let pro = models
            .iter()
            .find(|model| model["id"] == "qwen/pro")
            .expect("pro");
        assert_eq!(pro["maxInputTokens"], 1024000);
        assert_eq!(pro["supportsImages"], false, "图片未验证就不广告");
        assert_eq!(pro["supportsToolCall"], true);
        assert!(pro.get("credits").is_none(), "费率拿不到就不写");
    }

    #[test]
    fn extract_keys_accepts_several_shapes_and_filters_unknown() {
        let keys = extract_keys(&json!({
            "data": { "models": [
                { "key": "pro" },
                { "model": "flash" },
                { "id": "qwen/qwen3.8-max-preview" },
                { "id": "something-else" }
            ] }
        }));
        assert_eq!(keys, vec!["pro", "flash", "qwen3.8-max-preview"]);
        assert!(extract_keys(&json!({ "unexpected": true })).is_empty());
    }
}
