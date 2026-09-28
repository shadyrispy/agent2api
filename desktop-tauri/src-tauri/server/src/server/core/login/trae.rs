//! Trae 网页登录与通用 start / wait / cancel 状态表的衔接。
//!
//! ── 为什么这一家要另开一张待办表 ──────────────────────────
//! 授权地址**只能在进程内现造**：先绑一个 loopback 端口（回调 URL 的端口
//! 就是它），再拿这个端口去生成 PKCE 与设备密钥，最后拼进授权地址。于是
//! "这一轮登录"是一份**带着监听器的活对象**，不能序列化、也不能塞进
//! `LoginTaskState`（那张结构是所有 provider 共用的、`/wait` 直接序列化它 ——
//! 与 `login/autoclaw.rs` 同一理由）。
//!
//! 表里放 `Arc<Session>` 而不是 `Session`：等待方要在**放开待办表锁之后**
//! 才 await 回调（持锁等平台 = 用户在界面上点取消会卡在锁上）。取一份克隆
//! 出来等，锁就只保护那张表本身。
//!
//! ── 取消为什么必须显式 `close()` ────────────────────────────
//! 上面那个 Arc 的代价：待办表移除记录时，等待方还握着另一份引用，
//! 监听器不会 `Drop`，端口因此还不回来。所以取消/超时/完成三条收尾路径都
//! 显式调一次 `Session::close()`（见 `callback_server::CallbackListener::close`
//! 的说明）—— 否则就是 AutoClaw 那次「取消后端口被自己占着、立刻重试抢不到」
//! 的同一个 bug，只是这次占的是随机端口而不是登记端口。
//!
//! ── 同一时刻只允许一轮 ────────────────────────────────────
//! 不是洁癖而是参考实现的既有语义：新的开始会**关掉旧的监听**。两轮并存时
//! 回调落到哪个端口是不确定的，而授权码一次性 —— 并发等于让其中一轮必输。
//! 因此这张表按 state 存，但 `close` 是"清全部"：本家最多只该有一条。
//!
//! ── 超时为什么取任务表那一条而不是本家的 15 分钟 ───────────
//! 参考实现的登录 TTL 是 900 秒，但网关所有 provider 共用 `LOGIN_TIMEOUT_MS`
//! （5 分钟）与 `/wait` 协议；给一家单独延长会让界面"登录中"的计时与轮询
//! 节奏出现两种口径。5 分钟内没点完就重新发起一次，成本是一次点击。

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::server::core::providers::trae::credentials::{Credential, DEFAULT_VARIANT};
use crate::server::core::providers::trae::login::Session;
use crate::server::core::providers::{kind_id, ProviderKind};
use crate::server::logging;

use super::{finish_task_error, LoginService, LoginTaskHandle, LOGIN_TIMEOUT_MS};

impl LoginService {
    /// 发起一次 Trae 网页登录。
    ///
    /// 同步部分只做"建任务 + 登记 + 起后台"：授权地址要问一次上游
    /// （GetLoginGuidance，最多三个候选各 5 秒），不能在 HTTP 处理线程上等，
    /// 所以由后台任务造好后回填，调用方用 `wait_for_auth_url` 等它落地。
    pub fn start_trae_login(&self) -> Result<LoginTaskHandle, String> {
        let info = crate::server::core::endpoints::resolve_edition(Some(
            crate::server::core::endpoints::DEFAULT_EDITION,
        ));
        let handle = self.new_handle_for_provider(info, kind_id(ProviderKind::Trae));
        let state = format!("trae-{}", logging::now_ms());
        handle.update(|task| {
            task.state = Some(state.clone());
        });
        // 先收掉上一轮（close = 释放它占着的回调端口，等待方随之退出），
        // 再把新的登记进去 —— 顺序反了就会出现两轮并存的那个必输局面。
        self.close_trae_login();
        self.tasks.register(&state, handle.clone());
        let service = self.clone();
        let task = handle.clone();
        crate::spawn_task(async move {
            service.run_trae_login(task).await;
        });
        logging::log("[Login]", "发起 Trae 网页登录（等待浏览器回调…）");
        Ok(handle)
    }

    /// 后台那半个登录：造授权地址 → 等回调 → 换凭据 → 落账号。
    async fn run_trae_login(&self, handle: LoginTaskHandle) {
        let state = handle.snapshot().state.unwrap_or_default();
        let session = match Session::begin(DEFAULT_VARIANT, None).await {
            Ok(session) => Arc::new(session),
            Err(error) => {
                // 造不出授权地址 = 这一轮根本没有可等的东西。待办条目也要撤，
                // 否则界面显示"登录中"而永远等不到回调。
                self.close_trae_login();
                finish_task_error(&handle, &error);
                return;
            }
        };
        if handle.snapshot().canceled {
            session.close();
            self.close_trae_login();
            return;
        }
        let auth_url = session.auth_url.clone();
        self.trae_login()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(state.clone(), session.clone());
        handle.update(|task| {
            task.auth_url = Some(auth_url.clone());
        });

        let outcome =
            tokio::time::timeout(Duration::from_millis(LOGIN_TIMEOUT_MS), session.complete(None)).await;
        let credential: Credential = match outcome {
            Ok(Ok(credential)) => credential,
            Ok(Err(error)) => {
                self.close_trae_login();
                if handle.snapshot().canceled {
                    // 取消那一步由 `/cancel` 收尾（任务已从表里移除），这里不再
                    // 补一条错误 —— 否则两条路径会给出两个互相矛盾的结论。
                    return;
                }
                finish_task_error(&handle, &error.message);
                return;
            }
            Err(_) => {
                self.close_trae_login();
                finish_task_error(&handle, "Trae 网页登录超时（5 分钟），请重新发起");
                return;
            }
        };
        // 落账号与取消共用同一把任务锁：取消先发生就不落账号，落盘先发生则
        // 视为已完成（与 zcode / qoder 两条链逐字相同的处置）。
        let mut task = handle.lock();
        if task.done || task.canceled {
            drop(task);
            self.close_trae_login();
            return;
        }
        match self.store.add_trae_account(&credential, None, "web") {
            Ok(account) => {
                task.session = Some(json!({
                    "accountUid": account.get("id"),
                    "nickname": account.get("name"),
                    "edition": task.edition,
                    "provider": kind_id(ProviderKind::Trae),
                }));
                logging::log(
                    "[Login]",
                    &format!(
                        "✅ Trae 网页登录完成，账号已加入列表（{}）",
                        account.get("name").and_then(Value::as_str).unwrap_or("")
                    ),
                );
            }
            Err(error) => task.error = Some(error.message),
        }
        task.done = true;
        task.finished_at = Some(logging::now_ms());
        drop(task);
        self.close_trae_login();
    }

    /// 关掉所有进行中的 Trae 登录（本家同一时刻只有一轮，所以不传 state）。
    ///
    /// 顺序是"先摘表、后 close"：close 会让等待方以 `None` 退出，那条路径
    /// 也会走到这里（幂等），表里已经没有它了，就不会出现"边遍历边改"的锁重入。
    pub(crate) fn close_trae_login(&self) {
        let orphaned: Vec<Arc<Session>> = self
            .trae_login()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain()
            .map(|(_, session)| session)
            .collect();
        for session in orphaned {
            session.close();
        }
    }
}
