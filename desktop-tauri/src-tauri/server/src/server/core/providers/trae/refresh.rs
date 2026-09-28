//! Trae 的凭据续期（`ExchangeToken` 的 refreshToken 路径）。
//!
//! ── 为什么这条链的写法比别家更保守 ────────────────────────
//! `refreshToken` **每次换发都会轮换**（旧的当场作废）。这意味着任何一次
//! "发了请求但没把结果存下来"都是**把账号弄丢**：新串在内存里没落盘、
//! 旧串已经被服务端作废。所以这里三条规矩是硬性的：
//!   ① 失败**不改写**任何字段（参考实现同一条），旧的 refreshToken 仍可重试；
//!   ② 成功后**先落盘再往下走**（落盘侧的纪律在 `account_store::trae_accounts`）；
//!   ③ 同一凭据的并发续期走单飞表，只打上游一次 —— 否则两个请求各自拿到
//!      不同的新串，后存的那个把前一个覆盖掉，账号就废了。
//!
//! 到期判定不只看临期：参考实现还加了一条"签发龄超 15 天也换"（服务端有
//! 吊销旧凭据的风险），所以 `needs_refresh` 的两个条件都要传（见 `credentials.rs`）。

use std::time::Duration;

use serde_json::{Value, json};

use crate::server::errors::GatewayError;
use crate::server::core::providers::refresh_flight::{Join, Table};
use crate::server::core::proxies::ResolvedProxy;

use super::credentials::Credential;
use super::headers::CLIENT_USER_AGENT;
use super::http::{describe_candidates, post_json};

/// 提前续期的窗口（参考实现 `defaultRefreshSkew = 24h`）。
pub const REFRESH_LEAD_MS: i64 = 24 * 3600 * 1000;
/// 签发龄上限：超过就换，即使还没到期（`auth.issuedRotateMax` 同一条）。
pub const MAX_ISSUE_AGE_MS: i64 = 15 * 24 * 3600 * 1000;

/// 换证端点（相对各 OAuth host）。注意与**授权码**换证不是同一个路径：
/// 那条是 `/trae/api/v3/oauth/ExchangeToken`，见 `oauth.rs`。
pub const REFRESH_PATH: &str = "/cloudide/api/v3/trae/oauth/ExchangeToken";

/// 兜底 host（凭据里的 `apiHost` 不可用时依次试这两个）。
///
/// 顺序照参考实现的 `exchangeHosts(primary, oauth)`：账号 apiHost →
/// **OAuth host**（= `https://api.trae.cn`，登录时就写进凭据了）→ 平台备用源
/// （`api.trae.com.cn`）。先前写成"备用源在前"，只在 apiHost 为空时看得见差别
/// —— 而那正好是手工粘贴的凭据的常态。
const FALLBACK_HOSTS: [&str; 2] = ["https://api.trae.cn", "https://api.trae.com.cn"];

/// 单飞表：按 refreshToken 的指纹排队（同一个凭据的并发请求只有一个真打上游）。
static FLIGHTS: std::sync::OnceLock<Table<Credential>> = std::sync::OnceLock::new();

/// 候选 host 顺序：凭据里那份优先，然后是两个兜底（参考实现 `exchangeHosts`）。
///
/// 这条 host 表**不只服务续期**：`GetUserInfo`（登录后的身份回读）打的是同一组
/// host、同一份优先级，所以把它单独暴露出来，别让第二处再抄一遍顺序
/// （两处各写一份的结局就是"一处 5s、另一处 30s"那种漂移）。
pub fn candidate_hosts(api_host: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for host in [api_host.trim()].iter().chain(FALLBACK_HOSTS.iter()) {
        let host = host.trim_end_matches('/');
        if host.is_empty() {
            continue;
        }
        let host = if host.starts_with("http://") || host.starts_with("https://") {
            host.to_string()
        } else {
            format!("https://{host}")
        };
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

/// 续期端点的候选 URL（`candidate_hosts` × 本家的换证路径）。
pub fn refresh_candidates(api_host: &str) -> Vec<String> {
    candidate_hosts(api_host).into_iter().map(|host| format!("{host}{REFRESH_PATH}")).collect()
}

/// 续期请求体。`ClientID` 必须按 variant 选：参考实现里出过事故 ——
/// 裸凭据缺 variant 时一律解析成 cn 的 ClientID，SOLO 登录当场换发出
/// 跨类 token，之后积分/签到全 401（`code=1001`），而聊天还是正常的。
pub fn refresh_body(client_id: &str, refresh_token: &str) -> Value {
    json!({"ClientID": client_id, "RefreshToken": refresh_token, "ClientSecret": "-", "UserID": ""})
}

/// 解析换证响应。
///
/// 上游把令牌放在 `Result` 里，且字段名有两套写法（`Token` / `token` 等），
/// 所以取值要像参考实现那样逐个试；`TokenExpireAt` 是**毫秒**。
pub fn parse_refresh_response(body: &str) -> Result<(String, String, i64), String> {
    let parsed: Value = serde_json::from_str(body).map_err(|error| format!("换证响应不是合法 JSON：{error}"))?;
    let candidates = ["Result", "result"];
    for key in candidates {
        if let Some(object) = parsed.get(key).and_then(Value::as_object) {
            if let Some(token) = first_string(object, &["Token", "token", "AccessToken", "accessToken"]) {
                let refresh = first_string(object, &["RefreshToken", "refreshToken", "refresh_token"]).unwrap_or_default();
                let expires = ["TokenExpireAt", "tokenExpireAt", "ExpiresAt", "expiresAt"]
                    .iter()
                    .find_map(|field| object.get(*field).and_then(Value::as_i64).or_else(|| object.get(*field).and_then(Value::as_f64).map(|value| value as i64)))
                    .unwrap_or(0);
                return Ok((token, refresh, normalize_expires_at(expires)));
            }
        }
    }
    Err("换证响应里没有 access token".to_string())
}

/// 秒与毫秒的归一（同 `Credential::expires_at_ms` 的判据）。
pub fn normalize_expires_at(value: i64) -> i64 {
    if value <= 0 {
        return 0;
    }
    if value < 100_000_000_000 { value * 1000 } else { value }
}

fn first_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    // 空串不算命中：参考实现的 `jsonString` 把 `""` 与"没有这个键"归成同一件事
    // （`Token:""` 要往下一个键/下一层继续找，而不是当成换证成功）。
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str).filter(|text| !text.is_empty()))
        .map(str::to_string)
}

/// 打上游换新凭据（不含存储；调用方负责先落盘再继续）。
///
/// 返回的是**新凭据**（原凭据的其余字段带过来），失败时原凭据不受影响。
///
/// `urls` 由调用方给（生产路径就是 `refresh_candidates(&credential.api_host)`）。
/// 把候选列表做成入参而不是在函数里派生，是为了让"多 host 轮询""失败不改写"
/// "单飞合并"这三条能在测试里用**进程内 mock**验到：写死派生逻辑的测试会
/// 一路打到真实上游（v0 就踩过 —— 404 之后兜底 host 是 api.trae.cn，
/// 单测里那条假 refreshToken 真的被发出去了，判 401 还是 502 全看本机能不能
/// 联网，等于把一个纪律性断言挂在网络上）。
pub async fn refresh_once(
    credential: &Credential,
    urls: &[String],
    proxy: Option<&ResolvedProxy>,
) -> Result<Credential, GatewayError> {
    if !credential.can_refresh() {
        return Err(GatewayError::with_status(401, "Trae 凭据里没有 refreshToken，无法续期（请重新登录）"));
    }
    let client_id = super::oauth::client_id_for(credential.variant());
    let body = refresh_body(client_id, credential.refresh_token.trim());
    let headers = vec![("User-Agent", CLIENT_USER_AGENT.to_string())];
    let mut errors = Vec::new();
    for url in urls {
        match post_json(url, &body, &headers, Duration::from_secs(30), proxy).await {
            Ok(reply) if reply.status >= 400 => {
                errors.push(format!("{} => HTTP {} {}", url, reply.status, trim(&reply.body)));
            }
            Ok(reply) => match parse_refresh_response(&reply.body) {
                Ok((access_token, refresh_token, expires_at_ms)) => {
                    let mut next = credential.clone();
                    next.access_token = access_token;
                    // 上游没回新 refreshToken 时**保留旧的**：清空它等于让账号变成
                    // "过期后不可恢复"，而参考实现也是这么兜的。
                    if !refresh_token.is_empty() {
                        next.refresh_token = refresh_token;
                    }
                    next.expires_at = expires_at_ms;
                    return Ok(next);
                }
                Err(reason) => errors.push(format!("{} => {reason}", url)),
            },
            Err(error) => errors.push(format!("{} => {}", url, error.message)),
        }
    }
    // 4xx 语义原样透出（"凭据被拒（该重登）"与"上游挂了（该重试）"不能长一样）：
    // 全轮失败时按最后一个状态判，其它情况是 502。
    let status = if errors.iter().any(|error| error.contains("HTTP 401")) { 401 } else { 502 };
    Err(GatewayError::with_status(status, describe_candidates(urls, &errors)))
}

/// 带单飞的续期：并发请求只打上游一次，其余等结果。
pub async fn refresh_shared(
    credential: &Credential,
    urls: &[String],
    proxy: Option<&ResolvedProxy>,
) -> Result<Credential, GatewayError> {
    let key = crate::server::core::providers::refresh_flight::fingerprint(&credential.refresh_token);
    match FLIGHTS.get_or_init(Table::new).join(&key) {
        Join::Waiter(waiter) => waiter.wait().await,
        Join::Leader(leader) => {
            let result = refresh_once(credential, urls, proxy).await;
            leader.finish(result.clone());
            result
        }
    }
}

/// 上游错误体截断用（`www.*` 那类 host 会回一整页 HTML，不截会把日志淹掉）。
fn trim(text: &str) -> String {
    let collapsed: String = text.chars().filter(|character| !character.is_control()).collect();
    match collapsed.char_indices().nth(200) {
        Some((index, _)) => format!("{}…", &collapsed[..index]),
        None => collapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_order_puts_the_stored_host_first_and_dedups() {
        let urls = refresh_candidates("https://api.trae.cn/");
        assert_eq!(
            vec![
                "https://api.trae.cn/cloudide/api/v3/trae/oauth/ExchangeToken",
                "https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken"
            ],
            urls,
            "重复的兜底 host 不能出现两次"
        );
        assert_eq!(2, refresh_candidates("").len(), "没存 apiHost 时也要有两个兜底");
        // 参考实现 `exchangeHosts` 会给没有 scheme 的 host 补 https://（手工粘贴
        // 的凭据常写成 `api.trae.cn`），并去掉尾斜杠 —— 否则拼出来是
        // "api.trae.cn/cloudide/…"这种根本发不出去的东西。
        assert_eq!(
            vec![
                "https://api.trae.cn/cloudide/api/v3/trae/oauth/ExchangeToken",
                "https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken"
            ],
            refresh_candidates("api.trae.cn"),
            "裸域名要补 scheme"
        );
        assert_eq!(refresh_candidates("https://api.trae.cn"), candidate_hosts("api.trae.cn").into_iter().map(|host| format!("{host}{REFRESH_PATH}")).collect::<Vec<String>>(), "host 表与 URL 表必须是同一份优先级");
    }

    /// 续期请求体逐字节对答案卷（`trae-login-vectors.json` 的 `refreshBody` 段）。
    ///
    /// 之前只有下面那条"拿字面量自证"的用例，卷上这一段**一个字都没读过** ——
    /// 于是"键名改成 refresh_token"或"少一个 UserID 空串"这类漂移测不出来。
    /// 键序也要对得上：Go 的 marshal 按字母序，卷里就是那个序。
    #[test]
    fn the_refresh_body_matches_the_answer_sheet() {
        let sheet: serde_json::Value =
            serde_json::from_str(include_str!("vectors/trae-login-vectors.json")).expect("登录向量是合法 JSON");
        let want = sheet["refreshBody"].as_str().expect("refreshBody 段存在");
        let client_id = sheet["constants"]["soloClientID"].as_str().unwrap_or("en1oxy7wnw8j9n");
        let got = serde_json::to_string(&refresh_body(client_id, "RT-1")).expect("可序列化");
        assert_eq!(want, got.as_str(), "续期体的键、取值与顺序要和参考实现一致");
    }

    #[test]
    fn the_refresh_body_carries_the_variant_client_id() {
        let body = refresh_body("en1oxy7wnw8j9n", "RT-1");
        assert_eq!(
            r#"{"ClientID":"en1oxy7wnw8j9n","ClientSecret":"-","RefreshToken":"RT-1","UserID":""}"#,
            serde_json::to_string(&body).unwrap().as_str(),
            "四个键一个不能少：ClientSecret 是占位串，UserID 空串而不是 null"
        );
    }

    #[test]
    fn response_parsing_accepts_both_result_shapes() {
        let (token, refresh, expires) = parse_refresh_response(
            r#"{"Result":{"Token":"NEW","RefreshToken":"NEW-R","TokenExpireAt":1900000000000}}"#,
        )
        .expect("标准形状要能解析");
        assert_eq!("NEW", token);
        assert_eq!("NEW-R", refresh);
        assert_eq!(1_900_000_000_000, expires, "毫秒原样保留");
        let (token, refresh, expires) = parse_refresh_response(
            r#"{"result":{"accessToken":"B","tokenExpireAt":1900000000}}"#,
        )
        .expect("小写 result 也要能解析");
        assert_eq!("B", token);
        assert_eq!(1_900_000_000_000, expires, "秒要归一成毫秒");
        assert!(refresh.is_empty(), "没回 refreshToken 时给空串，由调用方保留旧值");
        // `Token:""` 不算命中，要接着找下一把键（参考实现 jsonString 的口径）。
        let (token, _, _) = parse_refresh_response(
            r#"{"Result":{"Token":"","AccessToken":"FROM-SECOND-KEY"}}"#,
        )
        .expect("空 Token 之后还有别的键就该继续找");
        assert_eq!("FROM-SECOND-KEY", token);
    }

    #[test]
    fn a_response_without_a_token_is_an_error_not_an_empty_credential() {
        for body in ["{}", r#"{"Result":{}}"#, "not json", r#"{"Result":{"Token":""}}"#] {
            assert!(parse_refresh_response(body).is_err(), "{body:?} 不能算换证成功");
        }
    }

    #[test]
    fn expiry_units_are_normalized_by_magnitude() {
        assert_eq!(1_900_000_000_000, normalize_expires_at(1_900_000_000));
        assert_eq!(1_900_000_000_000, normalize_expires_at(1_900_000_000_000));
        assert_eq!(0, normalize_expires_at(-5));
    }

    #[tokio::test]
    async fn a_refresh_failure_leaves_the_credential_untouched() {
        let upstream = MockUpstream::spawn(vec![(401, r#"{"code":1001}"#.to_string())]).await;
        let credential = Credential {
            access_token: "OLD".into(),
            refresh_token: "OLD-R".into(),
            api_host: upstream.base.clone(),
            ..Default::default()
        };
        let error = refresh_once(&credential, &upstream.urls(&[0]), None).await.expect_err("401 要报错");
        assert_eq!(401, error.status_code, "凭据被拒要原样透出 401，让上层判成「该重登」");
        assert_eq!("OLD-R", credential.refresh_token, "失败路径不能改写字段（旧串仍可重试）");
        assert_eq!(1, upstream.hits(), "只给了一个候选就只打一次");
    }

    #[tokio::test]
    async fn the_first_host_that_returns_a_token_wins() {
        let upstream = MockUpstream::spawn(vec![
            (404, "404 page not found".to_string()),
            (200, r#"{"Result":{"Token":"NEW","RefreshToken":"NEW-R","TokenExpireAt":1900000000000}}"#.to_string()),
        ])
        .await;
        let credential = Credential {
            access_token: "OLD".into(),
            refresh_token: "OLD-R".into(),
            ..Default::default()
        };
        // 两个候选都指向 mock（同一个地址会被去重，所以给两条不同路径）。
        let next = refresh_once(&credential, &upstream.urls(&[0, 1]), None).await.expect("第二个 host 该成功");
        assert_eq!("NEW", next.access_token);
        assert_eq!("NEW-R", next.refresh_token);
        assert_eq!(1_900_000_000_000, next.expires_at);
        assert_eq!(2, upstream.hits(), "第一个 404 之后确实换了 host");
    }

    #[tokio::test]
    async fn concurrent_refreshes_hit_upstream_once() {
        let upstream = MockUpstream::spawn(vec![]).await;
        upstream.push(200, r#"{"Result":{"Token":"NEW","RefreshToken":"NEW-R","TokenExpireAt":1900000000000}}"#.to_string());
        let credential = Credential {
            access_token: "OLD".into(),
            refresh_token: "ONE-FLIGHT-R".into(),
            api_host: upstream.base.clone(),
            ..Default::default()
        };
        let urls = upstream.urls(&[0]);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let credential = credential.clone();
            let urls = urls.clone();
            tasks.push(tokio::spawn(async move { refresh_shared(&credential, &urls, None).await.map(|value| value.access_token) }));
        }
        let mut tokens = Vec::new();
        for task in tasks {
            tokens.push(task.await.expect("任务不该 panic").expect("续期该成功"));
        }
        assert!(tokens.iter().all(|token| token == "NEW"), "所有等待者拿到的必须是同一份新串");
        // 单飞：8 个并发只打一次上游（mock 只排了一个响应，多打会拿到 500）
        assert_eq!(1, upstream.hits(), "并发应当合并成一次换发");
    }

    #[tokio::test]
    async fn tests_never_reach_the_real_upstream() {
        // 兜底 host 是 api.trae.cn —— 测试若图省事用 refresh_candidates() 当候选，
        // 假 refreshToken 会被真发出去（本机实测：真收到 20101「refresh token is
        // invalid」）。这条断言把"候选必须全部指向本地 mock"钉住：给一个空列表，
        // refresh_once 只能报 502，报 401 就说明有别的东西进来了。
        let credential = Credential { access_token: "OLD".into(), refresh_token: "R".into(), ..Default::default() };
        let error = refresh_once(&credential, &[], None).await.expect_err("没有候选就该失败");
        assert_eq!(502, error.status_code, "无候选 = 压根没发过请求，不是凭据被拒：{}", error.message);
        assert!(credential.can_refresh(), "这条测的是候选列表，不是凭据本身");
    }

    /// 进程内 mock 上游：按脚本依次回状态码，脚本空了回 500。
    ///
    /// 状态机类逻辑（多 host 轮询、失败不改写、单飞合并）用真 HTTP 打自己
    /// 起的监听器来验，比只测纯函数强得多，且零上游消耗。
    #[derive(Clone)]
    struct MockUpstream {
        pub base: String,
        script: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<(u16, String)>>>,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl MockUpstream {
        async fn spawn(script: Vec<(u16, String)>) -> Self {
            let subject = Self {
                base: String::new(),
                script: std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from(script))),
                hits: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let captured = subject.clone();
            let app = axum::Router::new().route("/{*path}", axum::routing::post(move |_req: axum::extract::Request| {
                let captured = captured.clone();
                async move {
                    let hits = captured.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let (status, body) = match captured.script.lock().unwrap().pop_front() {
                        Some(entry) => entry,
                        None => (500, format!("unexpected call {hits}")),
                    };
                    axum::http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body))
                        .unwrap()
                }
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("mock 监听");
            let address = listener.local_addr().expect("本地地址");
            tokio::spawn(async move { axum::serve(listener, app).await.ok(); });
            Self { base: format!("http://{address}"), script: subject.script, hits: subject.hits }
        }

        fn push(&self, status: u16, body: String) {
            self.script.lock().unwrap().push_back((status, body));
        }

        /// 造一份**只指向本 mock** 的候选列表（每个下标一条不同路径，
        /// 免得被去重成一条；mock 的路由是 `/{*path}`，什么路径都吃）。
        fn urls(&self, indexes: &[usize]) -> Vec<String> {
            indexes.iter().map(|index| format!("{}/mock-{index}", self.base)).collect()
        }

        fn hits(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
}
