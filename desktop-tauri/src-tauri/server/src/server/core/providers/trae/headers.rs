//! Trae SOLO 通道的请求头集合。
//!
//! ── 为什么把常量写死在这里而不是做成配置 ──────────────────
//! 这一批头不是"客户端偏好"，而是**上游用来选模型表和判血统的指纹**：
//! `X-Ide-Version-Code` 决定 `get_detail_param` 返回哪张目录表
//! （`20260716` 给 35 个、没有 glm-5.3；`20260820` 给 36 个、有），
//! 而"表里没有的模型"回的不是 404，是 HTTP 200 + 流内 4001。
//! 所以**头与目录必须同版本**：改了头不改目录缓存，就会出现
//! "广告出来的模型全 4001"。这两件事都写在本文件，就是为了别改一半。
//!
//! 取值来自参考实现 `plugins/trae/upstream/{constants,headers}.go`
//! （2026-09-03 真实客户端抓包），由 `vectors/trae-vectors.json` 的
//! `headers` 段逐头钉住。

use std::collections::BTreeMap;

pub const IDE_VERSION: &str = "0.1.61";
/// ⚠️ 与模型目录表绑定，见模块头。
pub const IDE_VERSION_CODE: &str = "20260820";
pub const APP_ID: &str = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8";
pub const DEVICE_BRAND: &str = "83DG";
pub const OS_VERSION: &str = "Windows 11 Pro";
pub const CLIENT_USER_AGENT: &str = "Trae/0.1.61";

/// 一份凭据里与头有关的四个值（其余字段不参与组头）。
#[derive(Clone, Debug, Default)]
pub struct HeaderIdentity<'a> {
    pub access_token: &'a str,
    pub uid: &'a str,
    pub machine_id: &'a str,
    pub device_id: &'a str,
}

/// `llm_utils_chat` / `get_detail_param` 要的头集合。
///
/// 三条容易漏的：
/// * 同一个 accessToken 要出现在**三个头**里（`Authorization` 带
///   `Cloud-IDE-JWT ` 前缀、`X-Cloudide-Token` 与 `X-Ide-Token` 是裸串）；
/// * `X-Uid` / `X-Machine-Id` / `X-Device-Id` **为空就不发这个头**，
///   发一个空值头上游会当成"另一个身份"；
/// * `Accept` 随流式与否变（`text/event-stream` / `application/json`）。
///
/// 返回 `BTreeMap` 只为测试好比对；出站时由调用方写进 `HeaderMap`。
pub fn solo_headers(identity: &HeaderIdentity<'_>, stream: bool) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Accept".to_string(),
        if stream { "text/event-stream" } else { "application/json" }.to_string(),
    );
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("User-Agent".to_string(), CLIENT_USER_AGENT.to_string());
    headers.insert("Authorization".to_string(), format!("Cloud-IDE-JWT {}", identity.access_token));
    headers.insert("X-Cloudide-Token".to_string(), identity.access_token.to_string());
    headers.insert("X-Ide-Token".to_string(), identity.access_token.to_string());
    if !identity.uid.is_empty() {
        headers.insert("X-Uid".to_string(), identity.uid.to_string());
    }
    if !identity.machine_id.is_empty() {
        headers.insert("X-Machine-Id".to_string(), identity.machine_id.to_string());
    }
    if !identity.device_id.is_empty() {
        headers.insert("X-Device-Id".to_string(), identity.device_id.to_string());
    }
    headers.insert("X-App-Id".to_string(), APP_ID.to_string());
    headers.insert("X-App-Version".to_string(), "default".to_string());
    headers.insert("X-Ide-Version".to_string(), IDE_VERSION.to_string());
    headers.insert("X-Ide-Version-Code".to_string(), IDE_VERSION_CODE.to_string());
    headers.insert("X-App-Version-Code".to_string(), IDE_VERSION_CODE.to_string());
    headers.insert("X-Ide-Version-Type".to_string(), "stable".to_string());
    headers.insert("X-Device-Type".to_string(), "windows".to_string());
    headers.insert("X-OS-Version".to_string(), OS_VERSION.to_string());
    headers.insert("X-Device-Brand".to_string(), DEVICE_BRAND.to_string());
    headers.insert("Request-Traffic-Type".to_string(), "prod".to_string());
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("vectors/trae-vectors.json");

    #[test]
    fn the_header_set_matches_the_reference_implementation() {
        let document: serde_json::Value = serde_json::from_str(VECTORS).expect("向量是合法 JSON");
        let cases = document["headers"].as_array().expect("headers 段是数组");
        assert!(!cases.is_empty());
        for case in cases {
            let auth = &case["auth"];
            let identity = HeaderIdentity {
                access_token: auth["accessToken"].as_str().unwrap_or_default(),
                uid: auth["uid"].as_str().unwrap_or_default(),
                machine_id: auth["machineID"].as_str().unwrap_or_default(),
                device_id: auth["deviceID"].as_str().unwrap_or_default(),
            };
            let got = solo_headers(&identity, case["stream"].as_bool().unwrap());
            // 头名**按大小写无关比对**：Go 的 `http.Header.Set` 会把键规范化
            // （源码写 `X-OS-Version`，向量里是 `X-Os-Version`），而 hyper/reqwest
            // 在 HTTP/1 与 HTTP/2 上写出的又是另一套（HTTP/2 强制小写）。
            // 头名本就大小写不敏感（RFC 9110 §5.1），这里追求逐字节相同
            // 既做不到也没意义 —— 与 codearts 那边"DPoP 不需要与 Go 对齐"同一条道理。
            // 值必须逐字节相同，那才是上游真正比的东西。
            let normalize = |map: &BTreeMap<String, String>| -> BTreeMap<String, String> {
                map.iter().map(|(key, value)| (key.to_lowercase(), value.clone())).collect()
            };
            let want: BTreeMap<String, String> = case["output"]
                .as_object()
                .expect("output 是对象")
                .iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap_or_default().to_string()))
                .collect();
            assert_eq!(normalize(&want), normalize(&got), "用例：{}", case["name"].as_str().unwrap_or("?"));
        }
    }

    #[test]
    fn the_same_token_is_carried_in_three_headers() {
        // 少一个头的后果是上游按"未登录"处理，而 HTTP 层是 200 —— 最难查的那种。
        let headers = solo_headers(&HeaderIdentity { access_token: "JWT", ..Default::default() }, true);
        assert_eq!("Cloud-IDE-JWT JWT", headers["Authorization"]);
        assert_eq!("JWT", headers["X-Cloudide-Token"]);
        assert_eq!("JWT", headers["X-Ide-Token"]);
    }

    #[test]
    fn empty_identity_fields_omit_the_header_rather_than_sending_empty() {
        let headers = solo_headers(&HeaderIdentity::default(), true);
        for key in ["X-Uid", "X-Machine-Id", "X-Device-Id"] {
            assert!(!headers.contains_key(key), "{key} 为空时不该出现");
        }
        // 令牌本身没有"省略"这一说：三个头恒在（值可以是空串，形状不变）。
        assert!(headers.contains_key("Authorization"));
    }
}
