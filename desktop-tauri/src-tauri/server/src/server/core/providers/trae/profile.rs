//! 登录完成后的**身份**从哪来（uid / nickname / 企业 id）。
//!
//! ── 为什么这是一条独立的链 ────────────────────────────────
//! 参考实现在这里摔过一次并被用户报告（v0.12.25）：同一个账号登两次，
//! 面板里出现**两个账号**。成因不是去重写错，而是身份取不到时兜底成了
//! "每次登录都新造一个 id"（用 per-login 的 `loginTraceID` 当文件名）——
//! 于是每次提交都落一个新凭据。修法是把身份的**来源优先级**定死：
//!
//! ```text
//!   GetUserInfo（权威，实时）→ 回调里的 userInfo 回显 → 每个 variant 一个
//!                                                        固定的 unknown 名
//! ```
//!
//! 最后那一级是**故意会撞车**的（同一谱系共用一个名字，重复登录覆盖同一条
//! 记录），因为"覆盖一条已知不完整的记录"远好于"多出一条没人认得的账号"。
//! 重新登录总会把它修好，而两个真来源都在时根本走不到这一步。
//!
//! ── 为什么 GetUserInfo 的失败不算登录失败 ──────────────────
//! 它只是读数。授权码换证已经成功、凭据已经可用，这时因为"昵称没拿到"就
//! 把整次登录判失败，等于把一次有效登录扔掉再让用户重做一次。参考实现
//! 同一条：`err != nil → log + proceed`。所以调用方**忽略**这里的错误，
//! 只记录。

use std::time::Duration;

use serde_json::Value;

use crate::server::errors::GatewayError;
use crate::server::core::proxies::ResolvedProxy;

use super::credentials::Credential;
use super::headers::{IDE_VERSION, CLIENT_USER_AGENT};
use super::http::{describe_candidates, post_json};
use super::oauth::query_pairs;
use super::refresh::candidate_hosts;

/// 身份端点（与续期共用同一组候选 host）。
pub const USER_INFO_PATH: &str = "/cloudide/api/v3/trae/GetUserInfo";

/// 一次登录读到的身份。
#[derive(Clone, Debug, Default)]
pub struct Identity {
    pub uid: String,
    pub nickname: String,
    pub enterprise_id: String,
    /// GetUserInfo 的原始回包（对拍与排障用；富 profile 的原料）。
    pub raw: String,
}

impl Identity {
    /// 把两个来源并成凭据最终的身份（优先级见模块头）。
    ///
    /// 参数顺序 = 优先级顺序：`authoritative` 是 GetUserInfo，
    /// `from_callback` 是回调回显。
    pub fn merged(authoritative: &Self, from_callback: &Self, variant: &str) -> Self {
        let uid = first_non_empty([&authoritative.uid, &from_callback.uid]).to_string();
        let nickname = first_non_empty([&authoritative.nickname, &from_callback.nickname]).to_string();
        Self {
            // unknown 兜底**只兜 uid**：昵称没有它就没有（界面显示成账号名即可，
            // 造一个假昵称反而让人以为真是账号名）。
            uid: if uid.is_empty() { unknown_uid_fallback(variant).to_string() } else { uid },
            nickname,
            enterprise_id: authoritative.enterprise_id.clone(),
            raw: authoritative.raw.clone(),
        }
    }
}

/// 每个 variant 一个**固定**的 unknown 身份（参考实现 `unknownUIDFallback`）。
///
/// 刻意不含任何 per-login 的东西（trace id / 时间戳）—— 那正是重复账号的源头。
pub fn unknown_uid_fallback(variant: &str) -> &'static str {
    match variant {
        "intl" => "unknown-intl",
        "solo" => "solo-unknown",
        _ => "unknown-cn",
    }
}

/// 从回调 query 里读 `userInfo` 回显（GetUserInfo 挂掉时的第二来源）。
///
/// 值是一个 JSON 对象，且可能被**再套一层字符串引号**（嵌套编码留下的），
/// 所以解一次不够。深度上限 2：真上游只多包一层，再多就是畸形输入，
/// 递归到底只会把一个坏回调变成一次长 CPU 占用。
pub fn callback_identity(query: &str) -> Identity {
    let pairs = query_pairs(query);
    for key in ["userInfo", "user_info", "UserInfo", "userinfo"] {
        let Some((_, raw)) = pairs.iter().find(|(name, _)| name == key).filter(|(_, value)| !value.trim().is_empty()) else {
            continue;
        };
        let found = identity_from_json(raw, 0);
        if !found.uid.is_empty() || !found.nickname.is_empty() {
            return found;
        }
    }
    Identity::default()
}

const UID_KEYS: [&str; 5] = ["UserID", "userId", "uid", "UID", "user_id"];
const NICKNAME_KEYS: [&str; 7] = ["ScreenName", "screenName", "Nickname", "nickname", "Name", "name", "displayName"];

fn identity_from_json(raw: &str, depth: usize) -> Identity {
    if depth > 2 {
        return Identity::default();
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Identity::default();
    }
    // 多包了一层引号（`"{\"UserID\":…}"`）→ 先解成内层字符串再递归。
    if trimmed.starts_with('"') {
        return match serde_json::from_str::<String>(trimmed) {
            Ok(inner) => identity_from_json(&inner, depth + 1),
            Err(_) => Identity::default(),
        };
    }
    if !trimmed.starts_with('{') {
        return Identity::default();
    }
    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return Identity::default();
    };
    Identity {
        uid: pick_string(&parsed, &UID_KEYS),
        nickname: pick_string(&parsed, &NICKNAME_KEYS),
        ..Default::default()
    }
}

fn pick_string(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::trim).filter(|text| !text.is_empty()))
        .unwrap_or_default()
        .to_string()
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = &'a String>) -> &'a str {
    // 只回引用，不回 String：调用方紧接着就要 clone 成它自己的字段，
    // 在这里先分配一份再丢是白做。
    values.into_iter().map(String::as_str).find(|text| !text.trim().is_empty()).unwrap_or_default()
}

/// 问上游要账号身份。
///
/// 请求侧三件事都是本家特有的（body 是 `ReqSource`/`IDEVersion` 而不是 OpenAI
/// 形状、令牌放 `X-Cloudide-Token` 且是**裸串**（不带 `Cloud-IDE-JWT ` 前缀 ——
/// 前缀只出现在 `Authorization` 那个头里，见 `headers.rs` 与参考实现
/// `OAuthHeaders` + `req.Header.Set("X-Cloudide-Token", a.JWT())`），host 表与
/// 续期同源），所以它不属于 `oauth.rs`（那条链只认识授权与换证）。
pub async fn get_user_info(credential: &Credential, proxy: Option<&ResolvedProxy>) -> Result<Identity, GatewayError> {
    let body = serde_json::json!({ "ReqSource": "IDE", "IDEVersion": IDE_VERSION });
    // User-Agent **必须显式给**：`egress` 的默认 UA 是 `"undici"`（那是给
    // workbuddy 计费接口挡刀用的），而参考实现在这条链上发的是 `Trae/0.1.61`。
    // 少这一个头不会报错，只会跟着上游哪天开始按 UA 画像时静默 401。
    let headers = vec![
        ("X-Cloudide-Token", credential.access_token.clone()),
        ("User-Agent", CLIENT_USER_AGENT.to_string()),
    ];
    let hosts = candidate_hosts(&credential.api_host);
    let mut errors = Vec::new();
    for host in &hosts {
        let url = format!("{host}{USER_INFO_PATH}");
        match post_json(&url, &body, &headers, Duration::from_secs(15), proxy).await {
            Ok(reply) if reply.status >= 400 => {
                errors.push(format!("{} => HTTP {} {}", url, reply.status, reply.body.chars().take(120).collect::<String>()));
            }
            Ok(reply) => {
                // 参考实现只读 `Result.{UserID,ScreenName,EnterpriseID}`；
                // 顶层同键是兜底（遇到过没有 Result 包装的回包时至少还能认出身份，
                // 认不出来也只是退回回调回显，不会写坏账号）。
                let parsed: Value = serde_json::from_str(&reply.body).unwrap_or(Value::Null);
                let result = result_of(&parsed);
                let source = result.as_ref().unwrap_or(&parsed);
                return Ok(Identity {
                    uid: pick_string(source, &UID_KEYS),
                    nickname: pick_string(source, &NICKNAME_KEYS),
                    enterprise_id: pick_string(source, &["EnterpriseID", "enterpriseId", "TenantID", "tenantId"]),
                    raw: reply.body,
                });
            }
            Err(error) => errors.push(format!("{} => {}", url, error.message)),
        }
    }
    Err(GatewayError::with_status(502, describe_candidates(&hosts, &errors)))
}

/// 上游把资料装在 `Result` 里（顶层也认，历史版本漂过）。
fn result_of(parsed: &Value) -> Option<Value> {
    for key in ["Result", "result"] {
        if let Some(object) = parsed.get(key).filter(|value| value.is_object()) {
            return Some(object.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_callback_user_info_echo_is_read_out_of_the_query() {
        // 生产实测的那条回调（键名、大小写、嵌套编码都照原样，值改成假数据）。
        let query = "isRedirect=true&scope=solo&authCodeInfo=%7B%22AuthCode%22%3A%22AC%22%7D\
                     &loginTraceID=t&host=https%3A%2F%2Fapi.trae.com.cn&userRegion=cn\
                     &userInfo=%7B%22ScreenName%22%3A%22%E7%94%A8%E6%88%B71%22%2C%22UserID%22%3A%22u-9%22%2C%22NonPlainTextMobile%22%3A%22176%2A%2A%2A78%22%7D";
        let identity = callback_identity(query);
        assert_eq!("u-9", identity.uid);
        assert_eq!("用户1", identity.nickname, "中文昵称要能还原（一次解码）");
    }

    #[test]
    fn an_extra_layer_of_string_quoting_is_peeled_not_treated_as_malformed() {
        // 嵌套编码留下的形态：`"{\"UserID\":…}"`。递归解一层，深度上限 2。
        let inner = r#"{"UserID":"u-deep","ScreenName":"深"}"#;
        let once = serde_json::to_string(inner).unwrap();
        let query = format!("userInfo={}", once);
        let identity = callback_identity(&query);
        assert_eq!("u-deep", identity.uid, "多包一层引号也要能读出来：{query}");
        assert_eq!("深", identity.nickname);
    }

    #[test]
    fn a_broken_or_empty_user_info_is_not_an_identity() {
        for query in [
            "userInfo=not-json",
            "userInfo=%7B%7D",
            "userInfo=%7B%22other%22%3A1%7D",
            "userInfo=",
            "nothing=1",
        ] {
            let identity = callback_identity(query);
            assert!(identity.uid.is_empty() && identity.nickname.is_empty(), "{query} 不该读出身份");
        }
    }

    #[test]
    fn the_identity_precedence_is_authoritative_then_echo_then_a_stable_unknown() {
        let from_get = Identity { uid: "u-get".into(), nickname: "Get".into(), ..Default::default() };
        let from_echo = Identity { uid: "u-echo".into(), nickname: "Echo".into(), ..Default::default() };
        let merged = Identity::merged(&from_get, &from_echo, "solo");
        assert_eq!("u-get", merged.uid, "GetUserInfo 是权威来源");
        assert_eq!("Get", merged.nickname);

        let only_echo = Identity::merged(&Identity::default(), &from_echo, "solo");
        assert_eq!("u-echo", only_echo.uid, "GetUserInfo 挂了就退回显回显");
        assert_eq!("Echo", only_echo.nickname);

        // 两个来源都没有：兜底名**每个 variant 固定**，所以重复登录会覆盖同一条
        // 记录而不是多出一条没人认得的账号（参考实现 v0.12.25 的成因）。
        let none = Identity::merged(&Identity::default(), &Identity::default(), "solo");
        assert_eq!("solo-unknown", none.uid);
        assert!(none.nickname.is_empty(), "造一个假昵称会让人以为那是账号名");
        assert_eq!("unknown-cn", Identity::merged(&Identity::default(), &Identity::default(), "cn").uid);
        assert_eq!("unknown-intl", Identity::merged(&Identity::default(), &Identity::default(), "intl").uid);
    }

    #[test]
    fn the_refresh_candidates_are_reused_for_the_identity_call() {
        // `GetUserInfo` 与续期同源同优先级：两处各写一份 host 表迟早漂移
        // （一处先试 api.trae.cn、另一处先试 api.trae.com.cn 就是漂移的开始）。
        let hosts = candidate_hosts("https://api.trae.cn");
        assert!(hosts.iter().any(|host| host == "https://api.trae.cn"));
        assert!(hosts.iter().any(|host| host == "https://api.trae.com.cn"));
        let url = format!("{}{USER_INFO_PATH}", hosts[0]);
        assert_eq!("https://api.trae.cn/cloudide/api/v3/trae/GetUserInfo", url);
    }
}
