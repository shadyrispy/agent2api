//! 千问办公的额度查询：三个池（daily / monthly / longterm）。
//!
//! 来源是 **`https://qwenwork.cn/user/wallets`**（注意不是网关域名 —— 这是
//! 站点侧的计费接口），Bearer 用 device token。返回形状：
//!
//! ```text
//!   data.daily_credits.total_balance     免费额度，每天 00:00（+08:00）重置
//!   data.monthly_credits.total_balance   订阅套餐内
//!   data.longterm_credits.total_balance  充值 / 赠送
//!   data.active_wallets.wallets[]        明细
//! ```
//!
//! ── 一个实测的坏读形态（必须校正，否则界面会谎报「今日额度用完了」）──
//! `wallets` 有时把 `daily` 报成 0，而网关的 `account-context` 里
//! `quota.remaining` 是**权威口径**且等于三池之和。所以当 `daily == 0` 时，
//! 拿 `remaining − monthly − longterm` 还原；只有当差值 > 0.005 才认定是坏读
//! 并采用（真·耗尽时差值≈0，不会把用光粉饰成还有额度）。
//!
//! **本家没有签到接口**：每日额度是自然日自动重置，不要造一个假签到按钮
//! （见 README 支持矩阵的「签到」列 —— 如实为 ✗）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use serde_json::{json, Value};

use crate::server::core::auth_http::send_raw;
use crate::server::core::account_store::AccountStore;
use crate::server::errors::GatewayError;

use super::constants;
use super::credentials;
use super::oauth;

/// 站点侧计费接口的主机（与 gateway 不同）
const WALLETS_HOST: &str = "https://qwenwork.cn";
const WALLETS_PATH: &str = "/user/wallets";
const REQUEST_TIMEOUT_MS: u64 = 15_000;

/// 查余额（`account_id` 为空 = 库里第一个启用的账号）
pub async fn query_usage(
    store: &AccountStore,
    account_id: &str,
) -> Result<Value, GatewayError> {
    let session = match store.qwenwork_session(account_id) {
        Some(session) => session,
        None => {
            return Err(GatewayError::with_status(
                401,
                if account_id.is_empty() {
                    "还没有可用的千问办公账号".to_string()
                } else {
                    format!("千问办公账号 {account_id} 不存在或不可用")
                },
            ));
        }
    };
    let credentials = credentials::from_session(&session)?;
    fetch_wallets(&credentials.access_token).await
}

/// 读三个池并归一成网关的 usage 形状。
async fn fetch_wallets(access_token: &str) -> Result<Value, GatewayError> {
    let (status, payload) = get_json_with_token(WALLETS_PATH, access_token).await?;
    if !(200..300).contains(&status) {
        return Err(GatewayError::with_status(
            502,
            format!("千问办公额度查询失败（HTTP {status}）"),
        ));
    }
    let payload = payload.ok_or_else(|| {
        GatewayError::with_status(502, "千问办公额度查询响应不是 JSON")
    })?;
    // 「三池全 0」的读抖动：隔 400ms 重试一次（参考实现同款）
    if all_zero(&payload) {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        if let Ok((status, Some(retried))) = get_json_with_token(WALLETS_PATH, access_token).await {
            if (200..300).contains(&status) && !all_zero(&retried) {
                return shape_usage(&retried, access_token).await;
            }
        }
    }
    shape_usage(&payload, access_token).await
}

fn all_zero(payload: &Value) -> bool {
    let data = payload.get("data").cloned().unwrap_or_else(|| payload.clone());
    let wallet_count = data
        .get("active_wallets")
        .and_then(|active| active.get("wallets"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    wallet_count == 0
        && number_of(&data, &["daily_credits", "total_balance"]).abs() < f64::EPSILON
        && number_of(&data, &["monthly_credits", "total_balance"]).abs() < f64::EPSILON
        && number_of(&data, &["longterm_credits", "total_balance"]).abs() < f64::EPSILON
}

/// 发一次 GET（带 Bearer 与 UA）。
async fn get_json_with_token(path: &str, access_token: &str) -> Result<(u16, Option<Value>), GatewayError> {
    let url = format!("{WALLETS_HOST}{path}");
    let headers = vec![
        (
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        ),
        ("User-Agent".to_string(), constants::USER_AGENT.to_string()),
    ];
    let response = send_raw("GET", &url, None, &headers, None, Some(REQUEST_TIMEOUT_MS))
        .await
        .map_err(|error| {
            if error.is_timeout() {
                GatewayError::with_status(504, "千问办公额度查询超时")
            } else {
                GatewayError::with_status(502, format!("千问办公额度查询失败: {error}"))
            }
        })?;
    Ok((response.status, response.payload))
}

/// 归一成网关的 usage 形状。
async fn shape_usage(payload: &Value, access_token: &str) -> Result<Value, GatewayError> {
    let data = payload.get("data").cloned().unwrap_or_else(|| payload.clone());
    let daily_raw = number_of(&data, &["daily_credits", "total_balance"]);
    // daily 报 0 的坏读：用 account-context 的 quota.remaining 还原
    let (daily, corrected) = if daily_raw.abs() < f64::EPSILON {
        match account_quota_remaining(access_token).await {
            Some(remaining) => {
                let restored = remaining - (monthly_of(&data) + longterm_of(&data));
                if restored > 0.005 {
                    (restored, true)
                } else {
                    (daily_raw, false)
                }
            }
            None => (daily_raw, false),
        }
    } else {
        (daily_raw, false)
    };
    Ok(shape_with(payload, daily, corrected))
}

fn monthly_of(data: &Value) -> f64 {
    number_of(data, &["monthly_credits", "total_balance"])
}

fn longterm_of(data: &Value) -> f64 {
    number_of(data, &["longterm_credits", "total_balance"])
}

/// 纯函数：给定三池里的 daily（已校正）与原始响应，产出 usage 形状。
fn shape_with(payload: &Value, daily: f64, corrected: bool) -> Value {
    let data = payload.get("data").cloned().unwrap_or_else(|| payload.clone());
    let monthly = monthly_of(&data);
    let longterm = longterm_of(&data);
    let available = daily + monthly + longterm;
    let wallets = vec![
        json!({
            "type": "daily",
            "displayName": "每日免费额度",
            "balance": round4(daily),
            "remaining": round4(daily),
        }),
        json!({
            "type": "monthly",
            "displayName": "套餐额度",
            "balance": round4(monthly),
            "remaining": round4(monthly),
        }),
        json!({
            "type": "longterm",
            "displayName": "长期额度",
            "balance": round4(longterm),
            "remaining": round4(longterm),
        }),
    ];
    json!({
        "available": round4(available),
        "unit": "积分",
        "wallets": wallets,
        // 本家没有「积分明细」列表：三池就是全部明细
        "credits": [],
        "raw": payload,
        "dailyCorrected": corrected,
    })
}

/// `account-context` 的 `data.quota.remaining`（权威口径；取不到给 None）
async fn account_quota_remaining(access_token: &str) -> Option<f64> {
    let url = format!("{}{}", constants::GATEWAY, constants::ACCOUNT_CONTEXT_PATH);
    let headers = vec![
        ("User-Agent".to_string(), constants::USER_AGENT.to_string()),
        ("Authorization".to_string(), format!("Bearer {access_token}")),
    ];
    let response = send_raw("GET", &url, None, &headers, None, Some(REQUEST_TIMEOUT_MS))
        .await
        .ok()?;
    let payload = response.payload?;
    payload
        .get("data")
        .unwrap_or(&payload)
        .get("quota")
        .and_then(|quota| quota.get("remaining"))
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

fn number_of(value: &Value, path: &[&str]) -> f64 {
    let mut current = value;
    for key in path {
        current = match current.get(*key) {
            Some(next) => next,
            None => return 0.0,
        };
    }
    current
        .as_f64()
        .filter(|number| number.is_finite())
        .unwrap_or(0.0)
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

/// 供 `models` 之外的调用点（签到中心、面板）判断「这个账号今天还有没有免费额度」
pub fn daily_remaining(usage: &Value) -> Option<f64> {
    usage
        .get("wallets")
        .and_then(Value::as_array)
        .and_then(|wallets| {
            wallets
                .iter()
                .find(|wallet| wallet.get("type").and_then(Value::as_str) == Some("daily"))
        })
        .and_then(|wallet| wallet.get("remaining").and_then(Value::as_f64))
}

/// 手机号脱敏的转发（登录落账号时用）
pub fn mask_phone(phone: &str) -> String {
    oauth::mask_phone(phone)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三池求和与键名形状（不联网：直接喂一个与上游同形的响应）
    #[test]
    fn three_pools_are_summed_and_named() {
        let payload = json!({
            "data": {
                "daily_credits": { "total_balance": 12.5 },
                "monthly_credits": { "total_balance": 80.0 },
                "longterm_credits": { "total_balance": 7.5 }
            }
        });
        // shape_with 是纯函数（daily=0 的校正分支才要再打上游，见 shape_usage）
        let shaped = shape_with(&payload, 12.5, false);
        assert_eq!(shaped.get("available"), Some(&Value::from(100.0)));
        assert_eq!(shaped.get("unit"), Some(&Value::from("积分")));
        let wallets = shaped.get("wallets").and_then(Value::as_array).expect("wallets");
        assert_eq!(wallets.len(), 3);
        for key in ["type", "displayName", "balance", "remaining"] {
            assert!(wallets[0].get(key).is_some(), "wallet 缺键 {key}");
        }
        assert_eq!(daily_remaining(&shaped), Some(12.5));
    }
}
