//! 千问办公登录：**OAuth Device Flow + PKCE，服务端轮询取票**。
//!
//! ── 与壳侧的关系：**不需要**任何回调通道 ──────────────────────
//! 授权页在网关上，回调落在网关自己的 `/oauth/callback`，**永远不回到本机**；
//! 用户完成授权后由本任务轮询 `deviceToken/poll` 取票（404 = 还没授权）。
//! 所以壳侧只负责开窗口，既不开监听、也不捕获自定义协议
//! （`qwenwork-cn://` 打不开是正常的）。
//!
//! ── 轮询节奏与失败的两类 ────────────────────────────────────
//! 固定间隔 2 秒；网络类失败**当 pending 继续等**（一次没问成不代表账号被拒），
//! 真正该终止的是：登录窗口超时（5 分钟）、取票返回业务错误、拿到票但读不到
//! uid（没有 uid 就签不出请求，落下来也是个废账号）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::time::Duration;

use serde_json::json;

use crate::server::core::providers::kind_id;
use crate::server::core::providers::qwenwork::{constants, oauth};
use crate::server::logging;

use super::{LoginService, LoginTaskHandle, finish_task_error};

impl LoginService {
    /// 发起千问办公登录：先把任务登记进状态表（auth_url 立刻就能给出 ——
    /// 授权地址是本地拼的，不需要网络往返），再起后台任务轮询取票。
    pub fn start_qwenwork_login(&self) -> Result<LoginTaskHandle, String> {
        let info = crate::server::core::endpoints::resolve_edition(None);
        let handle = self.new_handle_for_provider(
            info,
            kind_id(crate::server::core::providers::ProviderKind::Qwenwork),
        );
        let (login, url) = oauth::start().map_err(|error| error.message)?;
        let nonce = login.nonce.clone();
        handle.update(|task| {
            task.state = Some(nonce.clone());
            task.auth_url = Some(url);
        });
        self.tasks.register(&nonce, handle.clone());
        let service = self.clone();
        let task = handle.clone();
        crate::spawn_task(async move {
            service.run_qwenwork_login(task, login).await;
        });
        logging::log("[Login]", "发起千问办公网页登录（等待浏览器授权…）");
        Ok(handle)
    }

    async fn run_qwenwork_login(&self, handle: LoginTaskHandle, login: oauth::DeviceLogin) {
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(constants::DEVICE_FLOW_TIMEOUT_MS);
        loop {
            if handle.snapshot().canceled {
                return;
            }
            if tokio::time::Instant::now() >= deadline || login.expired() {
                finish_task_error(&handle, "千问办公登录超时（5 分钟），请重新发起");
                return;
            }
            tokio::time::sleep(Duration::from_millis(constants::DEVICE_POLL_INTERVAL_MS)).await;
            if handle.snapshot().canceled {
                return;
            }
            let bundle = match oauth::poll(&login).await {
                Ok(oauth::PollOutcome::Pending) => continue,
                Ok(oauth::PollOutcome::Authorized(bundle)) => bundle,
                Err(error) => {
                    // 取票端点的 5xx / 网络错：再等一轮（一次没问成不等于被拒）
                    if error.status_code >= 500 {
                        logging::verbose(
                            "[Login]",
                            &format!("千问办公取票暂时失败，继续等待: {}", error.message),
                        );
                        continue;
                    }
                    finish_task_error(&handle, &error.message);
                    return;
                }
            };
            // 拿到票 → 读账号信息（uid 是签名的硬前提，读不到就不落账号）
            let info = match oauth::account_context(&bundle.access_token).await {
                Ok(info) => info,
                Err(error) => {
                    finish_task_error(&handle, &error.message);
                    return;
                }
            };
            let phone = oauth::identities_phone(&bundle.access_token)
                .await
                .map(|phone| oauth::mask_phone(&phone))
                .unwrap_or_default();
            // 与取消共用任务锁：取消先发生就绝不落账号，落盘先发生则视为已完成
            let mut task = handle.lock();
            if task.done || task.canceled {
                return;
            }
            let payload = json!({
                "uid": info.uid,
                "accessToken": bundle.access_token,
                "refreshToken": bundle.refresh_token,
                "machineId": login.machine_id,
                "expiresAt": bundle.expires_at,
                "nickname": info.nickname,
                "email": info.email,
                "phone": phone,
                "planName": info.plan_name,
            });
            match self.store.add_qwenwork_account(&payload, None) {
                Ok(account) => {
                    task.session = Some(json!({
                        "accountUid": account.get("id"),
                        "nickname": account.get("name"),
                        "provider": "qwenwork",
                    }));
                    logging::log("[Login]", "✅ 千问办公网页登录完成，账号已加入列表");
                }
                Err(error) => task.error = Some(error.message),
            }
            task.done = true;
            task.finished_at = Some(logging::now_ms());
            return;
        }
    }
}
