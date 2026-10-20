//! COSY 协议签名与请求体编码 —— **Qoder 与千问办公（QwenWork）共用的协议栈**。
//!
//! 两个产品是同一套信封：同一个 `client_id`、同一个聊天路径
//! （`/algo/api/v2/service/pro/sse/agent_chat_generation`）、同一套
//! `Bearer COSY.<payload>.<sig>`、同一把服务端公钥、同一份 `Encode=1`
//! 自定义 base64。差异只有 `cosyVersion`、客户端身份头与身份 JSON 的字段
//! —— 所以算法只实现这一份，两家各自提供常量与请求头
//! （见 `qoder/cosy.rs` 与 `qwenwork/cosy.rs`）。
//!
//! ── 为什么不能只发 Bearer ───────────────────────────────────
//! 推理网关（`/algo/...` 这一族）不认普通 Bearer 令牌，而是一套**自签名**
//! 鉴权：
//!
//!   1. 组装用户身份 JSON；
//!   2. 生成一把一次性 AES 密钥，用它把身份 JSON 加密成 `info`；
//!   3. 用内置 RSA 公钥把该 AES 密钥加密成 `key`；
//!   4. 把 {version, requestId, info, cosyVersion, ideVersion} 序列化后 base64，
//!      得到 `payload`；
//!   5. 对 `payload \n key \n 时间戳 \n 请求体 \n 签名路径` 求 MD5，得到签名；
//!   6. 拼成 `Authorization: Bearer COSY.<payload>.<签名>`，并附一组 `Cosy-*` 头。
//!
//! 签名路径要**去掉 `/algo` 前缀、不含查询串** —— 服务端按同一规则校验。
//! **请求体参与签名**，所以调用顺序不能颠倒：先编码（[`encode_body`]）再签名。
//!
//! ── 两个原语为什么是手写的 ──────────────────────────────────
//! 项目里已有 `md-5` / `sha2` / `aes-gcm`（AutoClaw 用），但 **RSA 公钥加密**
//! 与 **AES-128-CBC** 没有现成实现：
//!   - RSA：只需「按 PKCS#1 v1.5 打包后做一次模幂」，指数固定 65537
//!     （`modpow` 约 17 次平方），`num-bigint` 一个依赖就够；
//!   - AES-CBC：`aes` 0.9 已在依赖树里（aes-gcm 拉的），CBC 链式异或 + PKCS#7
//!     补位是十几行确定性代码。
//!
//! 两者的**正确性已与 Node 的 `crypto` 逐字节对拍**（AES-CBC 密文、MD5 签名、
//! 编码后的请求体全部一致；RSA 走「Rust 加密 → Node 私钥解密」的往返验证）。
//!
//! ── 随机源 ──────────────────────────────────────────────────
//! AES 密钥、RSA 的 PS 填充、requestId 都必须是**不可预测**的随机值
//! （PS 若固定则 RSA 退化成确定性加密，是一条可被指纹化的特征）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic，取值走 Option 链，
//! 所有失败都转成 `GatewayError`。

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Block};
use base64::Engine as _;
use md5::{Digest, Md5};
use num_bigint::BigUint;

use crate::server::errors::GatewayError;

/// COSY 身份加密用的 RSA 公钥模数（1024 位，hex，无前导零）。
///
/// 这是**客户端内置的固定公钥**（参考实现 `RSA_PUBLIC_KEY` 的 PEM 正文），
/// 只用于加密一次性 AES 密钥，不是机密材料。指数固定 65537。
/// Qoder 与千问办公共用同一把（两个网关都接受用它签出来的请求，2026-10-14 实测）。
///
/// 公钥 PEM 与这里的模数是同一份数据的两种形态；导出方式：
/// 对 PEM 正文做 base64 解码 → DER 里 `02 81 81` 之后的 128 字节即模数，
/// 紧随其后的 `02 03 01 00 01` 即指数。
const RSA_MODULUS_HEX: &str = "c0f22307e5cd362e296bb04470f6de8fbf935ce24e8fcf511a0e2701329769c4a76e499bb938036a52af1eaf818cf79a2600620e3ce87e371d2ca6d85803606a1b3fa5e874643c9ed2db7e85673ef7227fca56e2e7c08f0927609bb896a9f24be1782099a66016a5bfdc3f1ff756bfc9e88d7b5dc5be30bf45a0223a00ebcecf";

/// RSA 公钥指数（源 PEM 里的 `02 03 01 00 01`）
const RSA_EXPONENT: u32 = 65537;

/// 自定义替换字母表（与标准 base64 字母表逐字符对应）
const CUSTOM_ALPHABET: &[u8] = b"_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!";
/// 标准 base64 字母表
const STD_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 一次签名会话的两把材料（`newSession` 的输出）。
///
/// `info` 与 `cosy_key` 在**一次会话内**可以复用（参考实现每个请求都新建一次，
/// 我们沿用同一语义：每次构造请求时 new 一个，生命周期只有一次请求）。
pub struct CosySession {
    /// RSA 加密后的一次性 AES 密钥（base64），进 `Cosy-Key` 头与签名
    pub cosy_key: String,
    /// AES 加密后的身份 JSON（base64），进 payload
    pub info: String,
    /// 本次请求的 requestId（UUID v4 形状，进 payload 与 `X-Request-Id`）
    pub request_id: String,
}

impl CosySession {
    /// 用身份 JSON 构造一次会话。
    ///
    /// `identity_json` 的**键顺序必须与参考实现一致**（各家的调用方负责）：
    /// 它会被 AES 加密进 `info`、再 base64 进 payload —— 整条字节串参与签名，
    /// 键序变了密文就不同（上游解密后按 JSON 语义读，理论上仍可用，但
    /// 「与参考实现逐字节一致」这条可对拍的硬保证会消失）。
    pub fn new(identity_json: &str) -> Result<Self, GatewayError> {
        // 一次性 AES 密钥：16 个 ASCII 字符（源实现在 UUID 去连字符后取前 16 位，
        // 这里取密码学随机串的前 16 位 —— 同一语义、更强的随机源）
        let secret = random_secret()?;
        let aes_key: String = secret.chars().take(16).collect();
        if aes_key.len() < 16 {
            return Err(GatewayError::with_status(500, "无法生成 COSY 签名密钥"));
        }
        let info = aes128_cbc_base64(&aes_key, identity_json.as_bytes())?;
        let cosy_key = rsa_encrypt_base64(&aes_key)?;
        Ok(Self {
            cosy_key,
            info,
            request_id: random_uuid()?,
        })
    }

    /// payload 的 base64（键序照抄参考：`version` / `requestId` / `info` /
    /// `cosyVersion` / `ideVersion`；手写而不是 `json!` 的理由见
    /// [`CosySession::new`] 的说明 —— serde_json 未开 `preserve_order`，
    /// `Value::Object` 是按键排序的 BTreeMap）。
    pub fn payload_b64(&self, cosy_version: &str) -> String {
        let payload_src = format!(
            "{{\"version\":\"v1\",\"requestId\":\"{}\",\"info\":\"{}\",\"cosyVersion\":\"{}\",\"ideVersion\":\"\"}}",
            self.request_id, self.info, cosy_version
        );
        base64::engine::general_purpose::STANDARD.encode(payload_src.as_bytes())
    }

    /// MD5(payload \n key \n 时间戳 \n 请求体 \n 签名路径)
    pub fn signature(&self, payload: &str, date: &str, body: &[u8], path: &str) -> String {
        let mut hasher = Md5::new();
        hasher.update(payload.as_bytes());
        hasher.update(b"\n");
        hasher.update(self.cosy_key.as_bytes());
        hasher.update(b"\n");
        hasher.update(date.as_bytes());
        hasher.update(b"\n");
        hasher.update(body);
        hasher.update(b"\n");
        hasher.update(path.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// 请求体的 MD5（个别家要单独的 `Cosy-Bodyhash` 头）
    pub fn body_hash(body: &[u8]) -> String {
        let mut hasher = Md5::new();
        hasher.update(body);
        format!("{:x}", hasher.finalize())
    }
}

/// `Bearer COSY.<payload>.<sig>`
pub fn compose_bearer(payload: &str, signature: &str) -> String {
    format!("Bearer COSY.{payload}.{signature}")
}

/// 当前时刻的秒级时间戳（`Cosy-Date` 与签名共用同一个值）。
pub fn now_timestamp() -> String {
    (crate::server::logging::now_ms() / 1000).to_string()
}

/// 请求体编码（源实现 `encodeBody`）：上游带 `Encode=1` 时请求体不是裸 JSON。
///
/// 三步都是**纯字节变换**，服务端按同一规则还原：
///   1. 对 JSON 字节做标准 base64，得到一段文本；
///   2. 把该文本按「尾段 / 中段 / 首段」重排（各段长度都是 ⌊n/3⌋，
///      余数留在中段，所以三段拼回来仍是原长）；
///   3. 逐字符做一次字母表替换（含把 `=` 换成 `$`）。
///
/// 签名算在**编码之后**的字节上（见 [`CosySession::signature`]）。
pub fn encode_body(payload: &[u8]) -> Vec<u8> {
    let standard = base64::engine::general_purpose::STANDARD.encode(payload);
    let bytes = standard.as_bytes();
    let length = bytes.len();
    let third = length / 3;

    let mut table = [0u8; 256];
    for (index, slot) in table.iter_mut().enumerate() {
        *slot = index as u8;
    }
    for (index, ch) in STD_ALPHABET.iter().enumerate() {
        table[*ch as usize] = CUSTOM_ALPHABET[index];
    }
    // base64 的填充符也要换掉
    table[b'=' as usize] = b'$';

    let mut out = Vec::with_capacity(length);
    // 尾段 → 中段 → 首段
    for index in (length - third)..length {
        out.push(table[bytes[index] as usize]);
    }
    for index in third..(length - third) {
        out.push(table[bytes[index] as usize]);
    }
    for index in 0..third {
        out.push(table[bytes[index] as usize]);
    }
    out
}

/// 一个字符串的 JSON 文本形态（带引号与转义）。
///
/// 用于手写身份 JSON / payload 时的取值转义。`serde_json::to_string` 对 `&str`
/// 就是把该串转义成 JSON 字符串，失败只可能是分配失败 —— 那时给一对空引号，
/// 签名会失败但不会 panic。
pub fn json_text(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

/// 参与签名的路径：去掉 `/algo` 前缀、不含查询串（源实现 `sigPathOf`）。
pub fn signature_path(request_url: &str) -> Result<String, GatewayError> {
    let parsed = url::Url::parse(request_url)
        .map_err(|_| GatewayError::with_status(500, "COSY 请求地址无效"))?;
    let path = parsed.path();
    Ok(path.strip_prefix("/algo").map(str::to_string).unwrap_or_else(|| path.to_string()))
}

/// 机器操作系统标识（源实现 `machineOs`）：`{arch}_windows` 这类形态。
pub fn machine_os() -> String {
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
    let platform = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    format!("{arch}_{platform}")
}

/// 生成一个不可猜测的 UUID v4（供会话/记录标识使用）。
pub fn random_uuid() -> Result<String, GatewayError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| GatewayError::with_status(500, "无法生成随机标识"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}

/// 32 字节的 URL-safe 随机串（一次性密钥的原料）。
fn random_secret() -> Result<String, GatewayError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| GatewayError::with_status(500, "无法生成安全的签名随机串"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// AES-128-CBC + PKCS#7，返回 base64 密文。
///
/// 密钥与 IV **都取同一段 16 字节**（源实现 `aesEncrypt` 的既有做法，
/// 不是这里的设计选择），所以调用方只需给一个 16 字符的 key。
fn aes128_cbc_base64(key16: &str, plaintext: &[u8]) -> Result<String, GatewayError> {
    if key16.len() != 16 {
        return Err(GatewayError::with_status(500, "COSY 签名密钥长度无效"));
    }
    let cipher = Aes128::new_from_slice(key16.as_bytes())
        .map_err(|_| GatewayError::with_status(500, "无法初始化 COSY 签名算法"))?;
    let iv = key16.as_bytes();

    // PKCS#7：补 1..16 字节，值等于补位长度
    let mut data = plaintext.to_vec();
    let pad = 16 - (data.len() % 16);
    data.extend(std::iter::repeat(pad as u8).take(pad));

    let mut previous = [0u8; 16];
    previous.copy_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        if chunk.len() != 16 {
            return Err(GatewayError::with_status(500, "COSY 签名分组长度异常"));
        }
        let mut block = [0u8; 16];
        for index in 0..16 {
            block[index] = chunk[index] ^ previous[index];
        }
        let mut encrypted = match Block::try_from(&block[..]) {
            Ok(block) => block,
            Err(_) => {
                return Err(GatewayError::with_status(500, "COSY 签名分组长度异常"));
            }
        };
        cipher.encrypt_block(&mut encrypted);
        out.extend_from_slice(&encrypted);
        previous.copy_from_slice(&encrypted);
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(&out))
}

/// RSA 公钥加密（PKCS#1 v1.5），返回 base64 密文。
///
/// 布局：`00 || 02 || PS || 00 || M`，PS 是**非零随机**字节
/// （源实现走 Node 的 `RSA_PKCS1_PADDING`，OpenSSL 用随机 PS）。
/// PS 固定会让 RSA 退化成确定性加密 —— 那是可被指纹化的特征，不要改。
fn rsa_encrypt_base64(plaintext: &str) -> Result<String, GatewayError> {
    let modulus = BigUint::parse_bytes(RSA_MODULUS_HEX.as_bytes(), 16)
        .ok_or_else(|| GatewayError::with_status(500, "COSY 签名公钥无效"))?;
    let key_len = ((modulus.bits() + 7) / 8) as usize;
    let message = plaintext.as_bytes();
    if message.len() + 11 > key_len {
        return Err(GatewayError::with_status(500, "COSY 签名内容过长"));
    }
    let ps_len = key_len - 3 - message.len();

    let mut ps = vec![0u8; ps_len];
    getrandom::getrandom(&mut ps)
        .map_err(|_| GatewayError::with_status(500, "无法生成 COSY 签名随机填充"))?;
    // PKCS#1 v1.5 要求 PS 全为非零字节：把抽到的 0 映射成 1
    for byte in ps.iter_mut() {
        if *byte == 0 {
            *byte = 1;
        }
    }

    let mut encoded = Vec::with_capacity(key_len);
    encoded.push(0x00);
    encoded.push(0x02);
    encoded.extend_from_slice(&ps);
    encoded.push(0x00);
    encoded.extend_from_slice(message);

    let cipher = BigUint::from_bytes_be(&encoded).modpow(&BigUint::from(RSA_EXPONENT), &modulus);
    // 定长输出（模数 1024 位 → 128 字节），不足时左侧补零
    let raw = cipher.to_bytes_be();
    if raw.len() > key_len {
        return Err(GatewayError::with_status(500, "COSY 签名结果长度异常"));
    }
    let mut out = vec![0u8; key_len];
    out[key_len - raw.len()..].copy_from_slice(&raw);
    Ok(base64::engine::general_purpose::STANDARD.encode(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与参考实现（Node `src/cosy.js`）**逐字节**对拍：固定输入 + 固定期望串。
    ///
    /// 期望串由 `node -e "require('./src/cosy').encode(...)"` 现生成
    /// （2026-10-20，dumate2api-ref）。编码是纯函数，任何一步顺序错
    /// （先换表再重排 / 填充符没换 `$`）都会让这条断言失败。
    #[test]
    fn encode_body_matches_the_reference_vector() {
        let sample = r#"{"model":"pro","messages":[{"role":"user","content":"你好，qwenwork"}]}"#;
        let encoded = encode_body(sample.as_bytes());
        assert_eq!(
            String::from_utf8(encoded).expect("ascii"),
            "*l*GzbPRL)ukbbB%%J(FhJ(WYPYKWxxw$M)umYKYu(%LBMn*JxjLN*BrBOjbuECLuEpmYKtu(CLuoByBEdYuYBrBO.LNkjiD(F^B"
        );
    }

    /// 签名与参考实现同一条公式（固定 payload/key/date/body/path 的 MD5）。
    #[test]
    fn signature_matches_the_reference_formula() {
        let session = CosySession {
            cosy_key: "key".to_string(),
            info: "info".to_string(),
            request_id: "rid".to_string(),
        };
        // 期望值由参考实现 `cosy.md5hex([payload, key, date, body, path].join('\n'))`
        // 在同一组输入上现算（2026-10-20）
        let signature = session.signature(
            "payload",
            "1700000000",
            "*l*GzbPRL)ukbbB%%J(FhJ(WYPYKWxxw$M)umYKYu(%LBMn*JxjLN*BrBOjbuECLuEpmYKtu(CLuoByBEdYuYBrBO.LNkjiD(F^B"
                .as_bytes(),
            "/api/v2/service/pro/sse/agent_chat_generation",
        );
        assert_eq!(signature, "7c4d6e57c9ce6dc00089d938d1016430");
    }

    /// 编码是纯字节变换：先重排再换表，解码后必须逐字节还原。
    #[test]
    fn encoded_body_still_carries_the_original_json() {
        let original = br#"{"model":"pro","messages":[{"role":"user","content":"hi"}]}"#;
        let encoded = encode_body(original);
        assert_ne!(encoded.as_slice(), original.as_slice());
        // 长度不变（base64 文本长度），只做置换与字母表替换
        let standard = base64::engine::general_purpose::STANDARD.encode(original);
        assert_eq!(encoded.len(), standard.len());
        // 逆变换：按同样的三段重排还原，再换回标准字母表后 decode
        let n = encoded.len();
        let a = n / 3;
        let mut restored = vec![0u8; n];
        for i in 0..n {
            let src = if i < a { n - a + i } else if i < n - a { i } else { i - (n - a) };
            restored[src] = encoded[i];
        }
        let mut back = [0u8; 256];
        for (index, slot) in back.iter_mut().enumerate() {
            *slot = index as u8;
        }
        for (index, ch) in STD_ALPHABET.iter().enumerate() {
            back[CUSTOM_ALPHABET[index] as usize] = *ch;
        }
        back[b'$' as usize] = b'=';
        let text: Vec<u8> = restored.iter().map(|byte| back[*byte as usize]).collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&text)
            .expect("编码必须可逆");
        assert_eq!(decoded.as_slice(), original.as_slice());
    }

    /// 签名路径去掉 `/algo`、丢掉查询串（服务端按同一规则校验）。
    #[test]
    fn signature_path_drops_algo_prefix_and_query() {
        let path = signature_path(
            "https://gateway.qwenwork.cn/algo/api/v2/service/pro/sse/agent_chat_generation?Encode=1",
        )
        .expect("path");
        assert_eq!(path, "/api/v2/service/pro/sse/agent_chat_generation");
    }

    /// 一次会话的 payload 必须能被 base64 解回带 cosyVersion 的 JSON。
    #[test]
    fn payload_contains_version_and_info() {
        let session = CosySession::new(r#"{"uid":"u"}"#).expect("session");
        let payload = session.payload_b64("1.1.52");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .expect("payload");
        let text = String::from_utf8(decoded).expect("utf8");
        assert!(text.starts_with("{\"version\":\"v1\","));
        assert!(text.contains("\"cosyVersion\":\"1.1.52\""));
        assert!(!text.contains(&session.cosy_key), "payload 里只有 info，没有 key");
    }
}
