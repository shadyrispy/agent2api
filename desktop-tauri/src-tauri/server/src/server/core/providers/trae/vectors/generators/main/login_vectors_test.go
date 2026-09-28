// 登录链路的向量生成器（package main 这一层：buildVerificationURI /
// parseCallbackQuery 用的候选键名 / ExchangeToken 的候选 URL 列表）。
//
// 为什么单独一个文件、且住在 main 包：这三个函数是**登录能不能成**的关键，
// 而它们的输出是一串有严格顺序的 query 与一组按优先级排的 URL ——
// 顺序与编码方式都不是风格问题（`auth_callback_url` 刻意**不**编码，
// 其余按 url.QueryEscape）。让参考实现自己把答案吐出来，Rust 侧照答案写。
//
// 用法：TRAE_LOGIN_VECTORS_OUT=/path/x.json go test -run TestGenerateLoginVectors ./
package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"

	"github.com/mmqz/cpa-multi-plugins/plugins/trae/upstream"
)

func TestGenerateLoginVectors(t *testing.T) {
	out := os.Getenv("TRAE_LOGIN_VECTORS_OUT")
	if out == "" {
		t.Skip("没给 TRAE_LOGIN_VECTORS_OUT，跳过向量生成")
	}

	// ── 1. 授权地址：四个 variant × 有/无 loginHost × 回调端口 ──
	var uris []map[string]any
	for _, variant := range []string{"cn", "solo", "intl", "solo-intl"} {
		for _, host := range []string{"www.trae.cn", "https://www.trae.cn/", "api.trae.cn"} {
			p := verificationURIParams{
				AuthFrom:      oauthAuthFor(variant),
				PluginVersion: oauthPluginVersion,
				ClientID:      upstream.ClientIDFor(variant),
				LoginTraceID:  "0f8fad5b-d9cb-469f-a165-70867728950e",
				CallbackURL:   "http://127.0.0.1:41890/authorize",
				MachineID:     "b3a1c2d4-0000-4000-8000-000000000001",
				DeviceID:      "1234567890123456",
				DeviceBrand:   oauthDeviceBrand,
				DeviceType:    oauthDeviceType,
				OSVersion:     oauthOSVersion,
				Env:           oauthEnv,
				AppVersion:    upstream.IdeVersion,
				AppType:       oauthAppType,
				CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				HideSaasLogin: oauthHideSaasLoginFor(variant),
			}
			uris = append(uris, map[string]any{
				"name": variant + " @ " + host, "variant": variant, "loginHost": host,
				"params": p, "output": buildVerificationURI(host, p),
			})
		}
	}
	// 需要编码的值（OS 版本带空格、回调 URL 刻意不编码）
	odd := verificationURIParams{
		AuthFrom: "solo", PluginVersion: "1.0.0", ClientID: upstream.ClientIDFor("solo"),
		LoginTraceID: "trace with space&plus=+", CallbackURL: "http://127.0.0.1:1/authorize?x=1",
		MachineID: "m", DeviceID: "d", DeviceBrand: "83DG", DeviceType: "windows",
		OSVersion: "Windows 11 Pro", Env: "prod", AppVersion: upstream.IdeVersion,
		AppType: "trae", CodeChallenge: "chalenge/plus+equal=", HideSaasLogin: true,
	}
	uris = append(uris, map[string]any{"name": "带空格与保留字符", "variant": "solo", "loginHost": "www.trae.cn", "params": odd, "output": buildVerificationURI("www.trae.cn", odd)})

	// ── 2. 回调 query：走**真实的 handleCallbackConn**（net.Pipe 喂 HTTP 请求），
	//    这样候选键名、优先级、错误分支的答案都是参考实现自己给的。
	callbacks := []map[string]any{}
	for _, raw := range []string{
		"authCode=AC-1&loginHost=www.trae.cn",
		"code=C-1&userTag=usttp",
		"refresh_token=RT-1&login_host=api.trae.cn",
		"authCode=AC-1&refreshToken=RT-1",
		"authCodeInfo=%7B%22authCode%22%3A%22AC-JSON%22%7D",
		"error=access_denied",
		"errorCode=20405",
		"isRedirect=false&authCode=AC-1",
		"nothing=1",
		"authCode=&code=&refreshToken=RT-only-empty-code",
		"consoleHost=www.trae.cn&Authorization_Code=AC-camel",
		"userInfo=%7B%22uid%22%3A%22u9%22%2C%22nickname%22%3A%22%E5%B0%8F%E6%98%8E%22%7D&authCode=AC-u",
	} {
		lc := &loginCtx{state: "s", variant: "solo"}
		server, client := net.Pipe()
		go func() {
			_, _ = client.Write([]byte("GET /authorize?" + raw + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
			_, _ = io.Copy(io.Discard, client)
			_ = client.Close()
		}()
		resolved := handleCallbackConn(server, lc)
		_ = server.Close()
		callbacks = append(callbacks, map[string]any{
			"query": raw, "resolved": resolved,
			"out": map[string]any{
				"authCode": lc.authCode, "refreshToken": lc.refreshToken, "loginHost": lc.loginHost,
				"userTag": lc.userTag, "uid": lc.cbUID, "nickname": lc.cbNickname, "error": errString(lc.err),
			},
		})
	}

	// ── 3. ExchangeToken / GetLoginGuidance 的候选 URL 顺序 ────
	exchange := []map[string]any{}
	for _, host := range []string{"", "www.trae.cn", "api.trae.cn", "https://www.trae.ai"} {
		exchange = append(exchange, map[string]any{"loginHost": host, "cn": authCodeExchangeURLsCN(host)})
	}
	guidance := map[string]any{"cn": traeCNLoginGuidanceURLs, "intl": traeIntlLoginGuidanceURLs}
	origins := map[string]any{
		"cnWithHost":  candidateAPIOorigins("www.trae.cn", true),
		"cnNoHost":    candidateAPIOorigins("", true),
		"intlWithHost": candidateAPIOorigins("www.trae.ai", false),
	}

	// ── 4. 刷新链路的请求体与响应解析 ──────────────────────────
	refreshBody, _ := json.Marshal(map[string]any{
		"ClientID": upstream.ClientIDFor("solo"), "RefreshToken": "RT-1", "ClientSecret": "-", "UserID": "",
	})
	device := buildOfficialDeviceInfo("d-1", "m-1", oauthPlatformCodeFor("solo"), oauthDeviceName, oauthDeviceBrand, upstream.IdeVersion, oauthDeviceType, oauthOSVersion, "PUBPEM")
	deviceRaw, _ := json.Marshal(device)

	document := map[string]any{
		"generatedFrom": map[string]any{"repo": "shadyrispy/cpa-multi-plugins", "package": "plugins/trae", "describe": os.Getenv("TRAE_REF_DESCRIBE")},
		"constants": map[string]any{
			"pluginVersion": oauthPluginVersion, "deviceName": oauthDeviceName, "deviceType": oauthDeviceType,
			"deviceBrand": oauthDeviceBrand, "osVersion": oauthOSVersion, "env": oauthEnv, "appType": oauthAppType,
			"ideVersion": upstream.IdeVersion, "loginTTLSeconds": int(loginTTL / 1e9),
			"oauthDefaultHost": oauthDefaultHost, "refreshSkewSeconds": int(defaultRefreshSkew / 1e9),
			"clientIDs": map[string]string{"cn": upstream.ClientIDFor("cn"), "solo": upstream.ClientIDFor("solo"), "intl": upstream.ClientIDFor("intl"), "soloIntl": upstream.ClientIDFor("solo-intl")},
			"platformCodes": map[string]string{"cn": oauthPlatformCodeFor("cn"), "solo": oauthPlatformCodeFor("solo")},
		},
		"verificationURI": uris, "callback": callbacks,
		"exchangeCandidates": exchange, "guidanceURLs": guidance, "candidateOrigins": origins,
		"refreshBody": string(refreshBody), "deviceInfo": string(deviceRaw),
	}
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("登录向量已写入 %s（%d 字节）", out, len(raw))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
