// 向量生成器：把本包对 SOLO 通道的全部「出站形状」判定导出成 JSON，
// 供 Rust 侧（agent2api `providers/trae`）逐字节对拍。
//
// 为什么要有这个文件（以及为什么它是 test 而不是生产代码）：
// agent2api 那份实现要复刻的不是上游接口，而是**这份 Go 实现的判定结果**
// —— body 白名单、四处 SOLO 变形、头集合、SSE→chunk 的转换、错误分类。
// 这些规则散在 payload.go / headers.go / solosse.go / client.go 里，
// 靠人读一遍再"照着写"必然漏（codearts 那次就是这么抓出好几个反向用例的）。
// 所以让参考实现自己把答案吐出来，Rust 侧只认这份答案。
//
// 用法：TRAE_VECTORS_OUT=/path/trae-vectors.json go test -run TestGenerateShapeVectors ./
package upstream

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/auth"
)

// ── 归一化：把每次运行都不一样的两个字段钉成常量 ──────────────────
// `id` 是 `chatcmpl-<UnixNano>`、`created` 是 `Unix()`，逐次不同。
// 归一后 Rust 侧只要保证「形状相同、这两个字段各自合规」即可逐字节比。
var (
	chunkID     = regexp.MustCompile(`"id":"chatcmpl-[0-9]+"`)
	chunkCreate = regexp.MustCompile(`"created":[0-9]+`)
)

func normalize(text string) string {
	text = chunkID.ReplaceAllString(text, `"id":"<ID>"`)
	return chunkCreate.ReplaceAllString(text, `"created":<CREATED>`)
}

// runStream 把一段上游 SSE 喂给 Stream()，返回**归一后的帧序列**
// （每帧形如 `event: error\ndata: "…"`，没有 event 行的只有 `data:`）。
func runStream(t *testing.T, input string) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := Stream(rec, strings.NewReader(input)); err != nil {
		t.Fatalf("Stream(%s) 报错：%v", input, err)
	}
	body := rec.Body.String()
	if !strings.HasSuffix(body, "\n\n") {
		t.Fatalf("输出没有以空行结尾：%q", body)
	}
	frames := strings.Split(strings.TrimSuffix(body, "\n\n"), "\n\n")
	out := make([]string, 0, len(frames))
	for _, frame := range frames {
		out = append(out, normalize(frame))
	}
	return out
}

func payloadCase(name, variant, resolved, input string) map[string]any {
	return map[string]any{"name": name, "variant": variant, "resolvedModel": resolved, "input": input, "output": string(PrepareBodyResolved([]byte(input), variant, resolved))}
}

func authOf(fields map[string]string) *auth.Auth {
	a := &auth.Auth{}
	if v, ok := fields["accessToken"]; ok {
		a.AccessToken = v
	}
	if v, ok := fields["uid"]; ok {
		a.UID = v
	}
	if v, ok := fields["machineID"]; ok {
		a.MachineID = v
	}
	if v, ok := fields["deviceID"]; ok {
		a.DeviceID = v
	}
	return a
}

func headersOf(fields map[string]string, stream bool) map[string]string {
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid", nil)
	SOLOHeaders(req, authOf(fields), stream)
	out := map[string]string{}
	for key, values := range req.Header {
		out[key] = strings.Join(values, ",")
	}
	return out
}

func ugHeadersOf(variant, accessToken, deviceID string) map[string]string {
	req, _ := http.NewRequest(http.MethodPost, "https://example.invalid", nil)
	UgHeaders(req, &auth.Auth{AccessToken: accessToken, Variant: variant, DeviceID: deviceID})
	out := map[string]string{}
	for key, values := range req.Header {
		joined := strings.Join(values, ",")
		// 这两个头每请求新生成（uuid-v4 / 00-<32hex>-<16hex>-01），逐次运行不同。
		// 钉成占位符；Rust 侧按**形状**断言（含 trace 尾段取自 request id 这条关系）。
		switch strings.ToLower(key) {
		case "x-request-id":
			joined = "<REQUEST_ID>"
		case "x-tt-trace-id":
			joined = "<TT_TRACE_ID>"
		}
		out[key] = joined
	}
	return out
}

// ── 额度与用量：把 UsageSummary / CreditsPoolInfo 摊平成可比的 map ──
// 指针字段（`-1` 无限之外的"字段缺失"）序列化成 null：Rust 侧必须区分
// 「上游没给」与「给了 0」，把缺失塌成 0 正是参考实现注释里点名要修的旧 bug
// （旧代码读一个不存在的 credits_limit，把 Free/SOLO 账户渲染成"剩余 0 积分"）。
func flattenSummary(sum *UsageSummary) map[string]any {
	intOr := func(v *int64) any {
		if v == nil {
			return nil
		}
		return *v
	}
	return map[string]any{
		"usageModel":  sum.UsageModel,
		"remainKnown": sum.RemainKnown,
		"remain":      sum.Remain,
		"fastLimit":   sum.FastLimit,
		"fastUsed":    sum.FastUsed,
		"used":        sum.Used,
		"total":       sum.Total,
		"fastRequestPer": intOr(sum.FastRequestPer),
		"soloParallel":   intOr(sum.SoloParallel),
		"soloPackage":    sum.SoloPackage,
		"planType":       sum.PlanType,
		"creditsPool": map[string]any{
			"remain": sum.CreditsPool.Remain, "known": sum.CreditsPool.Known, "unlimited": sum.CreditsPool.Unlimited,
		},
	}
}

// compactJSON 把 fixture 里为了可读性加的缩进/换行去掉，
// 这样 Rust 侧可以把同一段字符串原样喂给自己的解析器再逐字节比。
func compactJSON(raw string) string {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return strings.Join(strings.Fields(raw), "")
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return string(out)
}

func TestGenerateShapeVectors(t *testing.T) {
	out := os.Getenv("TRAE_VECTORS_OUT")
	if out == "" {
		t.Skip("没给 TRAE_VECTORS_OUT，跳过向量生成")
	}

	// ── 1. body：白名单 + SOLO 四处变形 ────────────────────────
	payload := []map[string]any{
		payloadCase("最小请求", "solo", "", `{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`),
		payloadCase("resolved 模型名赢过 body", "solo", "GLM-5.2", `{"model":"tr/kimi-k2.6","messages":[{"role":"user","content":"hi"}]}`),
		payloadCase("cn variant 也发 solo_work_lite", "cn", "", `{"model":"GLM-5.2","messages":[{"role":"user","content":"hi"}]}`),
		payloadCase("intl variant 同上", "intl", "", `{"model":"GLM-5.2","messages":[{"role":"user","content":"hi"}]}`),
		payloadCase("solo-intl 同上", "solo-intl", "", `{"model":"GLM-5.2","messages":[{"role":"user","content":"hi"}]}`),
		payloadCase("未知 variant 走默认 function", "bogus", "", `{"model":"GLM-5.2","messages":[{"role":"user","content":"hi"}]}`),
		payloadCase("字符串 content 归一成 text 块", "solo", "", `{"model":"m","messages":[{"role":"system","content":"s"}]}`),
		payloadCase("数组 content 原样透传", "solo", "", `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"u"}}]}]}`),
		payloadCase("developer 角色降成 system", "solo", "", `{"model":"m","messages":[{"role":"developer","content":"d"}]}`),
		payloadCase("assistant tool_calls 改名 function_call", "solo", "", `{"model":"m","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"ok"}]}`),
		payloadCase("孤儿 tool 结果被丢弃", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"},{"role":"tool","tool_call_id":"nope","content":"orphan"}]}`),
		payloadCase("空 assistant 占位被丢弃", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"},{"role":"assistant","content":""}]}`),
		payloadCase("tools 的 parameters 对象被字符串化", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}],"tools":[{"type":"function","function":{"name":"f","description":"d","parameters":{"type":"object","properties":{"x":{"type":"string"}}}}}]}`),
		payloadCase("tool_choice 对象被降成裸串", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}],"tool_choice":{"type":"function","function":{"name":"f"}}}`),
		payloadCase("tool_choice auto 保持", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}],"tool_choice":"auto"}`),
		payloadCase("max_tokens 缺省补一百万", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}]}`),
		payloadCase("max_tokens 给了就保留", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}],"max_tokens":1024}`),
		payloadCase("reasoning_effort auto 被丢", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}],"reasoning_effort":"auto"}`),
		payloadCase("reasoning_effort low 保留", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}],"reasoning_effort":"low"}`),
		payloadCase("采样参数与 stop 透传", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}],"temperature":0.3,"top_p":0.9,"presence_penalty":1,"frequency_penalty":2,"seed":7,"n":1,"stop":"END"}`),
		payloadCase("上游不认的键被丢掉", "solo", "", `{"model":"m","messages":[{"role":"user","content":"q"}],"user":"u","metadata":{"a":1},"response_format":{"type":"json_object"},"thinking":{"type":"enabled"},"stream_options":{"include_usage":true},"service_tier":"auto"}`),
		payloadCase("stream:false 也被强制成 true", "solo", "", `{"model":"m","stream":false,"messages":[{"role":"user","content":"q"}]}`),
		payloadCase("config_name 与 model 同值", "solo", "", `{"model":"kimi-k2.6","messages":[{"role":"user","content":"q"}]}`),
		payloadCase("带 -solo 后缀的入参被剥掉", "solo", "", `{"model":"GLM-5.2-solo","messages":[{"role":"user","content":"q"}]}`),
		payloadCase("带 -intl 后缀：solo 下也剥", "solo", "", `{"model":"GLM-5.2-intl","messages":[{"role":"user","content":"q"}]}`),
		payloadCase("名字里含斜杠是合法的", "solo", "", `{"model":"deepseek-ai/deepseek-v4-pro","messages":[{"role":"user","content":"q"}]}`),
		payloadCase("非法 JSON 原样返回", "solo", "", `not json`),
	}

	// ── 2. 模型名归一 ─────────────────────────────────────────
	sanitize := []map[string]any{}
	for _, pair := range [][2]string{{"GLM-5.2-solo", "solo"}, {"GLM-5.2-intl", "solo"}, {"GLM-5.2-intl", "intl"}, {"GLM-5.2-solo", "intl"}, {"deepseek-ai/deepseek-v4-pro", "solo"}, {"kimi-k2.6", "cn"}, {"a-solo-solo", "solo"}, {"-solo", "solo"}} {
		sanitize = append(sanitize, map[string]any{"model": pair[0], "variant": pair[1], "output": SanitizeModelName(pair[0], pair[1])})
	}

	// ── 3. 头集合（含身份字段缺失的组合）──────────────────────
	full := map[string]string{"accessToken": "JWT-ABC", "uid": "u-1", "machineID": "m-1", "deviceID": "d-1"}
	headerCases := []map[string]any{
		{"name": "流式全量", "auth": full, "stream": true, "output": headersOf(full, true)},
		{"name": "非流式", "auth": full, "stream": false, "output": headersOf(full, false)},
		{"name": "缺 uid", "auth": map[string]string{"accessToken": "JWT-ABC", "machineID": "m-1", "deviceID": "d-1"}, "stream": true, "output": headersOf(map[string]string{"accessToken": "JWT-ABC", "machineID": "m-1", "deviceID": "d-1"}, true)},
		{"name": "缺机器与设备", "auth": map[string]string{"accessToken": "JWT-ABC", "uid": "u-1"}, "stream": true, "output": headersOf(map[string]string{"accessToken": "JWT-ABC", "uid": "u-1"}, true)},
		{"name": "只有令牌", "auth": map[string]string{"accessToken": "JWT-ABC"}, "stream": true, "output": headersOf(map[string]string{"accessToken": "JWT-ABC"}, true)},
	}

	// ── 4. SSE → chunk（帧序列逐字节比）───────────────────────
	streamInputs := [][2]string{
		{"纯文本三段 + done + usage", "event: metadata\ndata: {\"session_id\":\"s1\",\"prompt_completion_id\":\"p1\"}\n\nevent: output\ndata: {\"response\":\"你\"}\n\nevent: output\ndata: {\"response\":\"好\"}\n\nevent: token_usage\ndata: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\nevent: done\ndata: {\"finish_reason\":\"stop\"}\n\n"},
		{"只有 reasoning", "event: output\ndata: {\"reasoning_content\":\"想想\"}\n\nevent: done\ndata: {\"finish_reason\":\"stop\"}\n\n"},
		{"tool 增量（function_call + 待剥字段）", "event: output\ndata: {\"tool_calls\":[{\"id\":\"c1\",\"type\":\"function\",\"function_call\":{\"name\":\"f\",\"arguments\":\"{\\\"x\\\":\",\"namespace\":\"n\",\"partial_arguments\":true}}]}\n\nevent: output\ndata: {\"tool_calls\":[{\"id\":\"c1\",\"type\":\"function\",\"function_call\":{\"arguments\":\"1}\"}}]}\n\nevent: done\ndata: {\"finish_reason\":\"tool_calls\"}\n\n"},
		{"上游没给 done（EOF 兜底 [DONE]）", "event: output\ndata: {\"response\":\"半句\"}\n\n"},
		{"空流（只有 [DONE]）", ""},
		{"注释行与 id 行被忽略", ": keep-alive\nid: 42\nevent: output\ndata: {\"response\":\"x\"}\n\nevent: done\ndata: {\"finish_reason\":\"stop\"}\n\n"},
		{"多行 data 累加", "event: output\ndata: {\"response\":\ndata: \"y\"}\n\nevent: done\ndata: {\"finish_reason\":\"stop\"}\n\n"},
		{"extra_info 帧（当前实现不处理）", "event: output\ndata: {\"response\":\"z\"}\n\nevent: extra_info\ndata: {\"anything\":1}\n\nevent: done\ndata: {\"finish_reason\":\"stop\"}\n\n"},
		{"流内错误 1005", "event: output\ndata: {\"response\":\"a\"}\n\nevent: error\ndata: {\"code\":1005,\"message\":\"plan limit\"}\n\n"},
		{"流内错误 4008", "event: error\ndata: {\"code\":4008,\"message\":\"Your requests have exceeded the quota\"}\n\nevent: done\ndata: {\"finish_reason\":\"stop\"}\n\n"},
		{"流内错误 4001", "event: error\ndata: {\"code\":4001,\"message\":\"We're sorry, the param is invalid. Please try with a valid param.\"}\n\n"},
		{"token_usage 是扁平形状", "event: output\ndata: {\"response\":\"f\"}\n\nevent: token_usage\ndata: {\"prompt_tokens\":9,\"completion_tokens\":4,\"total_tokens\":13}\n\nevent: done\ndata: {\"finish_reason\":\"stop\"}\n\n"},
		{"usage 之后没有 done", "event: token_usage\ndata: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n"},
		{"坏 JSON 的 output 帧", "event: output\ndata: {not json}\n\nevent: done\ndata: {\"finish_reason\":\"stop\"}\n\n"},
		{"CRLF 行尾", "event: output\r\ndata: {\"response\":\"crlf\"}\r\n\r\nevent: done\r\ndata: {\"finish_reason\":\"stop\"}\r\n\r\n"},
	}
	stream := []map[string]any{}
	aggregate := []map[string]any{}
	for _, pair := range streamInputs {
		stream = append(stream, map[string]any{"name": pair[0], "input": pair[1], "frames": runStream(t, pair[1])})
		doc, err := Aggregate(strings.NewReader(pair[1]))
		entry := map[string]any{"name": pair[0], "input": pair[1]}
		if err != nil {
			entry["error"] = err.Error()
		} else {
			normalized, _ := json.Marshal(doc)
			entry["output"] = normalize(string(normalized))
		}
		aggregate = append(aggregate, entry)
	}

	// ── 5. 错误分类 ───────────────────────────────────────────
	classify := []map[string]any{}
	for _, pair := range [][2]any{
		{200, `{}`}, {401, `{"error":"unauthorized"}`}, {403, `{"code":4008}`}, {404, `{"error":"not found"}`},
		{429, `{"error":"rate limit"}`}, {500, `oops`}, {502, `bad gateway`},
		{400, `{"code":4001,"msg":"We're sorry, the param is invalid"}`},
		{400, `{"code":1005,"msg":"plan limit"}`},
		{413, `too large`},
		{400, `{"msg":"prompt is too long for this model"}`},
		{400, `{"error":"This input is too large"}`},
		{400, `{"error":"plain client error"}`},
	} {
		classify = append(classify, map[string]any{"status": pair[0], "body": pair[1], "kind": Classify(pair[0].(int), pair[1].(string)).String()})
	}

	kinds := []map[string]any{}
	for _, pair := range [][2]any{
		{int64(1005), "plan limit"}, {int64(4008), "Your requests have exceeded the quota"},
		{int64(4001), "We're sorry, the param is invalid"}, {int64(4001), "prompt is too long, reduce input"},
		{int64(4023), "something"}, {int64(0), ""}, {int64(9074), "checkin crowded"},
	} {
		kinds = append(kinds, map[string]any{"code": pair[0], "msg": pair[1], "kind": (&SOLOStreamError{Code: pair[0].(int64), Msg: pair[1].(string)}).Kind().String()})
	}

	tooLarge := []map[string]any{}
	for _, msg := range []string{"prompt is too long", "input is too large", "This input is too large", "context length exceeded", "maximum context length", "nothing wrong here", ""} {
		tooLarge = append(tooLarge, map[string]any{"msg": msg, "tooLarge": MsgIndicatesInputTooLarge(msg)})
	}

	dead := []map[string]any{}
	for _, name := range []string{"agnes-2.0-flash", "deepseek-v4-flash", "DeepSeek-V4-Flash-Official", "DeepSeek-V4-Pro-Official", "glm-5.2", "kimi-k2.6", "seed_m8", "GLM-5.2"} {
		dead = append(dead, map[string]any{"configName": name, "soloAgentOnly": configIsSoloAgentOnly(name)})
	}

	// ── 6. 模型目录（get_detail_param）：请求形状 + 过滤结果 ────────
	// 这里走的是**真实调用链**（`Client.FetchModels` + 一个假 RoundTripper），
	// 不是把过滤规则重抄一遍：Rust 侧要复刻的正是"这个请求发出去、这份响应
	// 回来之后得到什么"。假上游顺手把请求记下来，于是请求侧（路径、body 里
	// 的 function、那几个身份头）也有了答案卷。
	//
	// 目录 fixture 特意含五类条目：正常可见 / invisible / 空 display_name /
	// config_switch=false / 两个布尔字段整个缺省，外加一条 solo_agent-only
	// 死配置（只有目录侧能证明"它被过滤掉了"，第 5 段那条只证明判定本身）。
	catalogFixture := `{"config_info_list":[
      {"config_name":"Doubao-Seed-2.1-Pro","config_switch":true,"is_invisible_to_user":false,
       "context_window_tokens":{"dev":256000},"display_config":{"display_name":"Seed-2.1-Pro"}},
      {"config_name":"seed-code-pro-0430","config_switch":true,"is_invisible_to_user":true,
       "context_window_tokens":{"dev":232768},"display_config":{"display_name":"Doubao-Seed-2.1-Pro"}},
      {"config_name":"custom_model_placeholder","config_switch":true,"is_invisible_to_user":false,
       "context_window_tokens":{"dev":128000},"display_config":{"display_name":""}},
      {"config_name":"legacy-model","config_switch":false,"is_invisible_to_user":false,
       "context_window_tokens":{"dev":100000},"display_config":{"display_name":"Legacy"}},
      {"config_name":"minimax-m3","config_switch":true,"is_invisible_to_user":false,
       "context_window_tokens":{"dev":200000},"display_config":{"display_name":"MiniMax-M3"}},
      {"config_name":"no-flags-model","context_window_tokens":{"dev":64000},
       "display_config":{"display_name":"NoFlags"}},
      {"config_name":"agnes-2.0-flash","config_switch":true,"is_invisible_to_user":false,
       "context_window_tokens":{"dev":32768},"display_config":{"display_name":"Agnes 2.0 Flash"}},
      {"config_name":"zero-window","config_switch":true,"is_invisible_to_user":false,
       "display_config":{"display_name":"ZeroWindow"}},
      {"config_name":"","display_config":{"display_name":"empty-id"}}
    ]}`
	var catalogRequest map[string]any
	client := testClient(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		catalogRequest = map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"body":   strings.TrimSpace(string(body)),
			"headers": headersOf(map[string]string{
				"accessToken": "JWT-ABC", "uid": "u-1", "machineID": "m-1", "deviceID": "d-1",
			}, false),
		}
		return jsonResp(200, catalogFixture), nil
	})
	models, err := client.FetchModels(&auth.Auth{AccessToken: "JWT-ABC", Variant: "solo", UID: "u-1", MachineID: "m-1", DeviceID: "d-1"})
	if err != nil {
		t.Fatalf("FetchModels 应当成功：%v", err)
	}
	catalog := []map[string]any{}
	for _, m := range models {
		catalog = append(catalog, map[string]any{"id": m.ID, "name": m.Name, "contextWindow": m.ContextWindow, "maxTokens": m.MaxTokens})
	}

	// ── 7. 额度与用量（ide_user_ent_usage / ide_user_pay_status）───────────
	// 同样是**真实调用链**：假 RoundTripper 记下两个请求（路径 / body / UgHeaders），
	// fixture 交给真实的解析与聚合函数。Rust 侧要复刻的是判定结果
	// （fast / basic / unknown、-1 无限、bonus 只加在可见包上、积分池的 Math.round、
	// quota 三层探测、pay_status 的 detail/quota 回退顺序），不是把规则重抄一遍。
	//
	// fixture 是照着参考实现自带测试与上游真实字段名写的，覆盖的都是
	// "写错就会静默显示一个假数字"的那几条：缺失 ≠ 0、隐藏包不算证据、
	// 已取消包要剔掉、originPayStatusData 只对 detail 生效（quota 那条路径没有）。
	var entUsageRequest, payStatusRequest map[string]any
	shapeClient := testClient(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		record := map[string]any{
			"method": r.Method, "path": r.URL.Path, "body": strings.TrimSpace(string(raw)),
			"headers": ugHeadersOf("solo", "at", "d-1"),
		}
		switch {
		case strings.HasSuffix(r.URL.Path, EpEntUsage):
			if entUsageRequest == nil {
				entUsageRequest = record
			}
			return jsonResp(200, `{"is_credits_billing":false,"user_entitlement_pack_list":[]}`), nil
		case strings.HasSuffix(r.URL.Path, EpPayStatus):
			if payStatusRequest == nil {
				payStatusRequest = record
			}
			return jsonResp(200, `{"code":0}`), nil
		}
		return jsonResp(500, "unexpected path: "+r.URL.Path), nil
	})
	if _, err := shapeClient.UserEntUsage(&auth.Auth{AccessToken: "at", Variant: "solo", DeviceID: "d-1"}); err != nil {
		t.Fatalf("UserEntUsage 取样失败：%v", err)
	}
	if _, err := shapeClient.PayStatus(&auth.Auth{AccessToken: "at", Variant: "solo", DeviceID: "d-1"}); err != nil {
		t.Fatalf("PayStatus 取样失败：%v", err)
	}

	usageCases := []struct {
		name string
		isCN bool
		body string
	}{
		{
			"basic 套餐：选中高优先级包，剩余额度=上限-已用",
			true,
			`{"is_credits_billing":true,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":6,"quota":{"basic_usage_limit":2000}},"usage":{"basic_usage_amount":300}},
			  {"entitlement_base_info":{"product_type":0,"quota":{"basic_usage_limit":500}}}]}`,
		},
		{
			"fast 速通：跨可见包求和，available=limit-used",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":6,"quota":{"premium_model_fast_request_limit":50}},"usage":{"premium_model_fast_amount":20}},
			  {"entitlement_base_info":{"product_type":0,"quota":{"basic_usage_limit":500}}}]}`,
		},
		{
			"fast 无限：任一包给 -1 则整体 -1（已用仍累计）",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":6,"quota":{"premium_model_fast_request_limit":-1}},"usage":{"premium_model_fast_amount":7}},
			  {"entitlement_base_info":{"product_type":1,"quota":{"premium_model_fast_request_limit":30}},"usage":{"premium_model_fast_amount":3}}]}`,
		},
		{
			"bonus：主额度超支时仍加可见包的正 bonus",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":1,"quota":{"basic_usage_limit":100,"bonus_usage_limit":50}},
			   "usage":{"basic_usage_amount":120,"bonus_usage_amount":10}}]}`,
		},
		{
			"隐藏包与已取消包不提供证据（fast 只剩可见包那份）",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":6,"is_hide":true,"quota":{"premium_model_fast_request_limit":9999}},"usage":{"premium_model_fast_amount":11}},
			  {"entitlement_base_info":{"product_type":4,"status":3,"quota":{"basic_usage_limit":8000}},"usage":{"basic_usage_amount":1}},
			  {"entitlement_base_info":{"product_type":1,"quota":{"premium_model_fast_request_limit":40}},"usage":{"premium_model_fast_amount":25}}]}`,
		},
		{
			"PROMO_CODE(product_type=3) 整个不参与",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":3,"quota":{"basic_usage_limit":99999}},"usage":{"basic_usage_amount":0}}]}`,
		},
		{
			"quota 三层探测：subscription_extra 那层",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":1,"quota":{},"product_extra":{"subscription_extra":{"quota":{"basic_usage_limit":300}}}},
			   "usage":{"basic_usage_amount":100}}]}`,
		},
		{
			"quota 三层探测：只有 package_extra 那层带 credits_limit",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":8,"product_extra":{"package_extra":{"quota":{"credits_limit":100}}}},
			   "usage":{"credits_amount":30.4}}]}`,
		},
		{
			"Free 且无 quota：unknown，绝不猜测剩余为 0",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":0,"display_desc":"免费"}}]}`,
		},
		{
			"积分池：逐包 max(limit-used,0) 后 Math.round",
			true,
			`{"is_credits_billing":true,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":1,"quota":{"credits_limit":100}},"usage":{"credits_amount":30.4}},
			  {"entitlement_base_info":{"product_type":8,"quota":{"credits_limit":10}},"usage":{"credits_amount":13.7}}]}`,
		},
		{
			"积分池 -1：整体不限（-1），但仍标 known",
			true,
			`{"is_credits_billing":true,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":100,"quota":{"credits_limit":-1}},"usage":{"credits_amount":42}},
			  {"entitlement_base_info":{"product_type":1,"quota":{"credits_limit":50}},"usage":{"credits_amount":10}}]}`,
		},
		{
			"is_credits_billing=true 而没有任何 credits_limit：按官方口径记 0",
			true,
			`{"is_credits_billing":true,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":1,"quota":{"basic_usage_limit":10}},"usage":{"basic_usage_amount":4}}]}`,
		},
		{
			"status 缺省视为 active（判反了会把整张清单剔空）",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":1,"quota":{"basic_usage_limit":60}},"usage":{"basic_usage_amount":20}}]}`,
		},
		{
			"国际版优先级没有 100/5：同一份包在 isCN=false 下选另一包",
			false,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":100,"quota":{"basic_usage_limit":9000}},"usage":{"basic_usage_amount":1}},
			  {"entitlement_base_info":{"product_type":6,"quota":{"basic_usage_limit":700}},"usage":{"basic_usage_amount":100}}]}`,
		},
		{
			"display_desc 优先于 product_type 映射成套餐名",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[
			  {"entitlement_base_info":{"product_type":4,"quota":{"basic_usage_limit":10}},"display_desc":"Pro+ 年度","usage":{"basic_usage_amount":2}}]}`,
		},
		{
			"空清单：unknown 且积分池未知",
			true,
			`{"is_credits_billing":false,"user_entitlement_pack_list":[]}`,
		},
	}
	usageVectors := []map[string]any{}
	for _, tc := range usageCases {
		c := testClient(func(r *http.Request) (*http.Response, error) { return jsonResp(200, tc.body), nil })
		res, err := c.UserEntUsage(&auth.Auth{AccessToken: "at", Variant: "solo", DeviceID: "d-1"})
		if err != nil {
			t.Fatalf("usage fixture %q 解析失败：%v", tc.name, err)
		}
		sum := SummarizeUsage(res.UserEntitlementPackList, tc.isCN)
		sum.CreditsPool = CreditsPoolUsage(res.UserEntitlementPackList, res.IsCreditsBilling)
		score, scoreKnown := PackListRemain(res.UserEntitlementPackList, tc.isCN)
		entry := flattenSummary(&sum)
		entry["name"] = tc.name
		entry["isCN"] = tc.isCN
		entry["body"] = compactJSON(tc.body)
		entry["isCreditsBilling"] = res.IsCreditsBilling
		entry["score"] = score
		entry["scoreKnown"] = scoreKnown
		var productType any
		plan := "Unknown"
		if selected := SelectActivePack(res.UserEntitlementPackList, tc.isCN); selected != nil {
			productType = selected.EntitlementBaseInfo.ProductType
			if d := strings.TrimSpace(selected.DisplayDesc); d != "" {
				plan = d
			} else {
				plan = ProductTypeIdentity(selected.EntitlementBaseInfo.ProductType, tc.isCN)
			}
			remain, ok := selected.PackRemain()
			entry["selectedRemain"] = remain
			entry["selectedRemainKnown"] = ok
		} else {
			entry["selectedRemain"] = nil
			entry["selectedRemainKnown"] = false
		}
		entry["plan"] = plan
		entry["selectedProductType"] = productType
		usageVectors = append(usageVectors, entry)
	}

	payStatusCases := []struct{ name, body string }{
		{"顶层 detail/quota 直接命中",
			`{"code":0,"user_pay_identity_str":"free","detail":{"fast_request_per":1000,"can_get_express_status":1},"quota":{"solo_agent_parallel_limit":3,"enable_solo_agent":true}}`},
		{"只有 entitlementInfo 嵌套",
			`{"code":0,"entitlementInfo":{"detail":{"fastRequestPer":500},"quota":{"solo_agent_parallel_limit":2}}}`},
		{"originPayStatusData 只补 detail（quota 没有这层回退）",
			`{"code":0,"originPayStatusData":{"detail":{"fast_request_per":700}},"quota":{"enable_solo_web":false}}`},
		{"quota 只出现在 originPayStatusData → 取不到",
			`{"code":0,"originPayStatusData":{"quota":{"solo_agent_parallel_limit":9}},"detail":{"can_get_express_status":0}}`},
		{"两个键名同现时先命中的那个赢（fast_request_per 在前）",
			`{"code":0,"detail":{"fast_request_per":10,"fastRequestPer":99}}`},
		{"键存在但不是数字：跳过、继续找下一键下一层",
			`{"code":0,"detail":{"fast_request_per":"abc"},"entitlementInfo":{"detail":{"fastRequestPer":42}}}`},
		{"enable_solo_* 全 false → 无 SOLO 包",
			`{"code":0,"quota":{"enable_solo_agent":false,"enable_solo_builder":false,"enable_solo_coder":false,"enable_solo_lite":false,"enable_solo_web":false}}`},
		{"enable_solo_coder=true → 有 SOLO 包",
			`{"code":0,"quota":{"enable_solo_agent":false,"enable_solo_coder":true}}`},
		{"布尔位置放数字：不认（Go 的 bool 反序列化失败即视为无）",
			`{"code":0,"quota":{"enable_solo_agent":1}}`},
		{"code 非 0（面板按 code==0 才采纳这些维度）",
			`{"code":1001,"user_pay_identity_str":"Pro","detail":{"fast_request_per":5}}`},
		{"身份串带空格 → 去掉",
			`{"code":0,"user_pay_identity_str":"  Free  "}`},
		{"什么都没有 → 全 null、planType 空串",
			`{"code":0}`},
	}
	payStatusVectors := []map[string]any{}
	for _, tc := range payStatusCases {
		c := testClient(func(r *http.Request) (*http.Response, error) { return jsonResp(200, tc.body), nil })
		ps, err := c.PayStatus(&auth.Auth{AccessToken: "at", Variant: "solo", DeviceID: "d-1"})
		if err != nil {
			t.Fatalf("pay_status fixture %q 解析失败：%v", tc.name, err)
		}
		intOr := func(v *int64) any {
			if v == nil {
				return nil
			}
			return *v
		}
		payStatusVectors = append(payStatusVectors, map[string]any{
			"name": tc.name, "body": compactJSON(tc.body), "code": ps.Code,
			"fastRequestPer": intOr(ps.FastRequestPer()), "canGetExpressStatus": intOr(ps.CanGetExpressStatus()),
			"soloParallel": intOr(ps.SoloParallelLimit()), "soloPackage": ps.HasSoloPackage(),
			"planType": ps.PlanIdentity(),
		})
	}

	freePlan := []map[string]any{}
	for _, pair := range [][2]string{{"免费", ""}, {"Free", ""}, {" Pro ", ""}, {"", "free"}, {"", "标准 Free 版"}, {"Ultra", ""}, {"", ""}, {"", "免费"}} {
		freePlan = append(freePlan, map[string]any{"plan": pair[0], "planType": pair[1], "isFree": IsFreePlan(pair[0], pair[1])})
	}
	productTypeIdentity := []map[string]any{}
	for _, pair := range [][2]any{{100, true}, {100, false}, {6, true}, {5, true}, {5, false}, {4, false}, {1, false}, {9, true}, {8, true}, {0, true}, {7, true}, {3, true}} {
		productTypeIdentity = append(productTypeIdentity, map[string]any{
			"productType": pair[0], "isCN": pair[1], "identity": ProductTypeIdentity(pair[0].(int), pair[1].(bool))})
	}
	ugHeaderCases := []map[string]any{}
	for _, variant := range []string{"solo", "cn", "intl", "solo-intl", "bogus"} {
		ugHeaderCases = append(ugHeaderCases, map[string]any{
			"variant": variant, "output": ugHeadersOf(variant, "at", "d-1")})
	}

	document := map[string]any{
		"generatedFrom": map[string]any{"repo": "shadyrispy/cpa-multi-plugins", "package": "plugins/trae/upstream", "describe": describeVersion()},
		"notes": []string{
			"stream.frames 里 `id` 与 `created` 已归一成 <ID> / <CREATED>（逐次运行不同）。",
			"payload.output 是 PrepareBodyResolved 的**字节**；空 resolvedModel 表示按 body 里的 model 走。",
			"dead.soloAgentOnly 为 true 的配置在 solo_work_lite 通道必定流内 4001，目录要过滤掉。",
			"catalog.request 是 FetchModels 实际发出的请求（假 RoundTripper 记的），catalog.output 是过滤后的清单顺序即上游给的顺序。",
			"usageRequest/payStatusRequest 里 x-request-id / x-tt-trace-id 钉成占位符（每请求新生成）；Rust 侧按形状断言，并保留「trace 尾段 = request id 去横线前 16 位」这条关系。",
			"usage[].remainKnown=false 时 remain/score 是零值不是读数；面板必须显示「--」而不是 0（参考实现修过的正是这个）。",
			"payStatus 的 quota 回退只有 quota → entitlementInfo.quota 两层，originPayStatusData 仅对 detail 生效。",
		},
		"payload": payload, "sanitizeModelName": sanitize, "headers": headerCases,
		"stream": stream, "aggregate": aggregate,
		"classify": classify, "streamErrorKind": kinds, "tooLargeMessage": tooLarge, "deadModel": dead,
		"catalogRequest": catalogRequest, "catalog": catalog, "catalogFixture": strings.TrimSpace(catalogFixture),
		"endpoints": map[string]any{"ugHost": UgHost, "entUsage": EpEntUsage, "payStatus": EpPayStatus},
		"usageRequest": entUsageRequest, "payStatusRequest": payStatusRequest,
		"ugHeaders": ugHeaderCases, "usage": usageVectors, "payStatus": payStatusVectors,
		"isFreePlan": freePlan, "productTypeIdentity": productTypeIdentity,
	}
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("序列化向量失败：%v", err)
	}
	if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("写 %s 失败：%v", out, err)
	}
	t.Logf("向量已写入 %s（%d 字节）", out, len(raw))
}

// describeVersion 尽量给出"这份答案是谁算的"；拿不到 git 标签也不影响生成。
func describeVersion() string {
	if v := os.Getenv("TRAE_REF_DESCRIBE"); v != "" {
		return v
	}
	return "unknown（未给 TRAE_REF_DESCRIBE）"
}
