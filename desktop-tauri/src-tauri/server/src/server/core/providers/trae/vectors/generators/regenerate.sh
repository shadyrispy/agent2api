#!/usr/bin/env bash
# 重新生成 Trae 的对拍答案卷（vectors/trae-vectors.json、trae-login-vectors.json）。
#
# ── 为什么生成器住在这里而不是参考实现仓库里 ──────────────────
# 这两个生成器**必须**待在参考实现的包里才能跑（它们要调
# `buildVerificationURI` / `handleCallbackConn` / `PrepareBodyResolved` 这些
# 包内函数，跨包拿不到）。但"必须能放进去跑"不等于"应该留在别人仓库里"：
# 收进自己仓库、把外部仓库当只读，才不会哪天参考仓库被重置/切分支就把
# 答案卷的生产线弄丢（这条线一旦丢，Rust 侧那些"逐字节对拍"的测试就退化成
# 没人能重跑的化石）。所以这里的规矩是：**投放 → 跑 → 立刻清走**。
#
# 用法：
#   bash regenerate.sh                       # 用默认的参考实现路径
#   TRAE_REF_DIR=/path/to/cpa-multi-plugins bash regenerate.sh
#
# 跑完记得 `git diff --stat` 看一眼答案卷变了什么 —— 变了就说明参考实现的
# 形状漂了，Rust 侧对应用例此时应该红，那才是本来的目的。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VECTORS_DIR="$(dirname "$HERE")"
REF="${TRAE_REF_DIR:-$HOME/Documents/yas2/cpa-deploy/cpa-multi-plugins}"

if [[ ! -d "$REF/plugins/trae/upstream" ]]; then
  echo "✗ 找不到参考实现：$REF/plugins/trae/upstream" >&2
  echo "  用 TRAE_REF_DIR=… 指过去（它是只读依赖，本脚本不会留下任何文件）" >&2
  exit 1
fi

# 生成器 → 参考实现的落点（一一对应，别改成通配：错一个包名就是静默不产出）。
declare -a DROP=(
  "upstream/trae_vectors_test.go:plugins/trae/upstream"
  "main/login_vectors_test.go:plugins/trae"
)
PLACED=()
cleanup() {
  # 无论成功、失败还是中途退出，参考实现的工作树都要回到干净状态。
  local f
  for f in "${PLACED[@]-}"; do
    [[ -n "$f" ]] && rm -f "$f"
  done
}
trap cleanup EXIT

for pair in "${DROP[@]}"; do
  src="$HERE/${pair%%:*}"
  dst="$REF/${pair##*:}/$(basename "${pair%%:*}")"
  [[ -f "$src" ]] || { echo "✗ 生成器缺件：$src" >&2; exit 1; }
  cp "$src" "$dst"
  PLACED+=("$dst")
  echo "→ 投放 $(basename "$dst") 到 ${pair##*:}/"
done

# Go 走本机 mise 那份（这台机器上 go.dev 的 DNS 不通，GOTOOLCHAIN=local
# 防止 go 自己去下载工具链）。没装 mise 就用 PATH 里的 go。
if command -v mise >/dev/null 2>&1; then
  GO=(mise exec -- go)
else
  GO=(go)
fi
export GOTOOLCHAIN=local
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
# ⚠️ CGO 必须开着：参考实现的 `main.go` 走 cgo 与 CPA 宿主桥（`import "C"`），
# `CGO_ENABLED=0` 会让那些文件整个不参与编译，报错还全是
# `undefined: loginCtx / providerName / accountCacheEntry` 这种"符号凭空消失"
# 的样子 —— 看着像参考仓库坏了，实际是自己把它的源码关在门外（本机实测）。
# 与 `bash build.sh darwin arm64` 那条构建口径一致（CGO_ENABLED=1）。
export CGO_ENABLED=1
cd "$REF/plugins/trae"
# 不带 `--dirty`：投放进去的这两个生成器本身就是"脏"，写进答案卷的出处
# 应当是**参考实现那一版代码**，而不是"我这次跑的时候工作树临时多了两个文件"。
export TRAE_REF_DESCRIBE="$(cd "$REF" && git describe --always)"
export TRAE_VECTORS_OUT="$VECTORS_DIR/trae-vectors.json"
export TRAE_LOGIN_VECTORS_OUT="$VECTORS_DIR/trae-login-vectors.json"

"${GO[@]}" test -run TestGenerateShapeVectors ./upstream/
"${GO[@]}" test -run TestGenerateLoginVectors ./

for f in "$TRAE_VECTORS_OUT" "$TRAE_LOGIN_VECTORS_OUT"; do
  [[ -s "$f" ]] || { echo "✗ $f 没产出（生成器被跳过？检查 -run 与 TRAE_*_OUT）" >&2; exit 1; }
  wc -c "$f" | awk '{printf "✓ 答案卷 %s (%d 字节)\n", $2, $1}'
done
echo "✓ 参考实现工作树已复原：$(cd "$REF" && git status --porcelain | wc -l | tr -d ' ') 处改动"
