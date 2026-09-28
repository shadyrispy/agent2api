# Trae 对拍答案卷的生成器

这两个文件不是本仓库的代码，而是**参考实现**（`cpa-multi-plugins` 的
`plugins/trae`）的包内测试 —— 它们必须放在那个包里才跑得起来（要调
`PrepareBodyResolved` / `SOLOHeaders` / `Stream` / `Aggregate` / `Classify` /
`buildVerificationURI` / `handleCallbackConn` 这些非导出函数）。

但"必须能放进去跑"不等于"应该留在别人仓库里"。所以规矩是**投放 → 跑 → 立刻清走**：

```
bash regenerate.sh                    # 默认参考实现在 ~/Documents/yas2/cpa-deploy/cpa-multi-plugins
TRAE_REF_DIR=/path/to/cpa-multi-plugins bash regenerate.sh
```

落点按下划线还原：

| 这里 | 参考实现里的位置 |
| --- | --- |
| `upstream/trae_vectors_test.go` | `plugins/trae/upstream/`（`package upstream`） |
| `main/login_vectors_test.go` | `plugins/trae/`（`package main`） |

产物就是本目录（`vectors/`）里的两份 JSON，被 Rust 侧用 `include_str!` 直接吃进去：

- `trae-vectors.json` —— 出站 body 27 例、请求头 5 例、SSE 帧 15、非流式聚合 15、
  错误分类 13、错误码 7、"输入过大"文案 7、死配置名单 8。
- `trae-login-vectors.json` —— 授权地址 13 条（逐字节）、回调解析 12 条、
  换证候选 4 组、guidance URL、候选 origin、刷新请求体、DeviceInfo、常量表。

跑完如果答案卷变了，说明**参考实现那一侧的形状漂了** —— 此时 Rust 侧对应的
用例应当变红，那正是这套东西的目的（`cargo test -p agent2api-server trae`）。

两个坑（都踩过，别再来一遍）：

- **`CGO_ENABLED` 必须是 1**。参考实现的 `main.go` 走 cgo 与宿主桥，关掉 cgo
  会让那些文件整个不参与编译，错误长得像"符号凭空消失"
  （`undefined: loginCtx / providerName / accountCacheEntry`）。
- **`git describe` 不带 `--dirty`**。投放进去的生成器本身就把工作树弄脏了，
  答案卷里的出处要指参考实现那一版代码，而不是"我这次跑的时候多了两个文件"。
