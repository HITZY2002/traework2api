package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"traework2api/internal/auth"
	"traework2api/internal/upstream"
)

// TRAE SOLO 授权登录（与 login.sh 一致）：
//   1. 服务端生成 machine_id/device_id + 授权 URL
//   2. 用户浏览器登录后跳到 127.0.0.1 回调（打不开属正常）
//   3. 用户粘贴完整回调链接 → ExchangeToken → GetUserInfo → 落盘 → 热加载
const (
	traeConsoleHost   = "https://www.trae.cn"
	traeAuthCallback  = "http://127.0.0.1:18080/authorize"
	oauthSessionTTL   = 15 * time.Minute
	traePluginVersion = "2.3.62834"
)

type oauthSession struct {
	ID        string
	MachineID string
	DeviceID  string
	AuthURL   string
	CreatedAt time.Time
}

type oauthStore struct {
	mu   sync.Mutex
	byID map[string]*oauthSession
}

func newOAuthStore() *oauthStore {
	return &oauthStore{byID: map[string]*oauthSession{}}
}

func (s *oauthStore) put(sess *oauthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.byID[sess.ID] = sess
}

func (s *oauthStore) get(id string) *oauthSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	return s.byID[id]
}

func (s *oauthStore) del(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

func (s *oauthStore) gcLocked() {
	now := time.Now()
	for id, sess := range s.byID {
		if now.Sub(sess.CreatedAt) > oauthSessionTTL {
			delete(s.byID, id)
		}
	}
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newHexID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// buildTraeAuthURL 构造 www.trae.cn/authorization 登录链接（与 login.sh 参数一致）。
func buildTraeAuthURL(machineID, deviceID string) string {
	q := url.Values{}
	q.Set("login_version", "1")
	q.Set("auth_from", "solo")
	q.Set("login_channel", "native_ide")
	q.Set("plugin_version", traePluginVersion)
	q.Set("auth_type", "local")
	q.Set("client_id", upstream.ClientID)
	q.Set("redirect", "0")
	q.Set("login_trace_id", newHexID()[:16])
	q.Set("auth_callback_url", traeAuthCallback)
	q.Set("machine_id", machineID)
	q.Set("device_id", deviceID)
	q.Set("x_device_id", deviceID)
	q.Set("x_machine_id", machineID)
	q.Set("x_device_brand", "PC")
	q.Set("x_device_type", "PC")
	q.Set("x_os_version", "1.0")
	q.Set("x_app_version", upstream.IdeVersion)
	q.Set("x_app_type", "stable")
	return traeConsoleHost + "/authorization?" + q.Encode()
}

// adminOAuthStart 发起 TRAE 授权，返回浏览器登录 URL + session（绑定 machine/device id）。
func (h *Handler) adminOAuthStart(w http.ResponseWriter, r *http.Request) {
	if h.cfg.AuthDir == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "auth_dir 未配置"})
		return
	}
	machineID := newHexID()
	deviceID := newHexID()
	authURL := buildTraeAuthURL(machineID, deviceID)
	id := newSessionID()
	h.oauth.put(&oauthSession{
		ID:        id,
		MachineID: machineID,
		DeviceID:  deviceID,
		AuthURL:   authURL,
		CreatedAt: time.Now(),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"session_id": id,
		"auth_url":   authURL,
		"expires_in": int(oauthSessionTTL.Seconds()),
		"message":    "请在浏览器打开授权链接登录；完成后把地址栏完整回调链接粘贴回来",
		"flow":       "callback_paste", // 前端据此显示粘贴框（非 poll）
	})
}

// adminOAuthFinish 解析用户粘贴的回调 URL，换 token 落盘并热加载。
func (h *Handler) adminOAuthFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID   string `json:"session_id"`
		CallbackURL string `json:"callback_url"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &req)
	}
	if req.SessionID == "" {
		req.SessionID = r.URL.Query().Get("session_id")
	}
	if req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "status": "error", "message": "session_id required"})
		return
	}
	if strings.TrimSpace(req.CallbackURL) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "status": "error", "message": "请粘贴浏览器地址栏的完整回调链接"})
		return
	}
	sess := h.oauth.get(req.SessionID)
	if sess == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "status": "error", "message": "会话不存在或已过期，请重新发起授权"})
		return
	}
	if h.cfg.AuthDir == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "status": "error", "message": "auth_dir 未配置"})
		return
	}

	refreshToken, userInfo, userJWT, err := parseTraeCallback(req.CallbackURL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "status": "error", "message": "回调解析失败: " + err.Error()})
		return
	}

	uid := strField(userInfo, "UserID")
	nickname := strField(userInfo, "ScreenName")
	entID := strField(userInfo, "TenantID")
	if entID == "" {
		entID = strField(userInfo, "EnterpriseID")
	}

	// 容错：回调缺 refreshToken 时尝试 userJwt
	if refreshToken == "" {
		refreshToken = strField(userJWT, "RefreshToken")
	}
	jwtToken := strField(userJWT, "Token")

	a := &auth.Auth{
		RefreshToken: refreshToken,
		AccessToken:  jwtToken, // 可能为空，Exchange 后覆盖
		ApiHost:      upstream.OAuthHost,
		Domain:       "trae.cn",
		MachineID:    sess.MachineID,
		DeviceID:     sess.DeviceID,
		UID:          uid,
		Nickname:     nickname,
		EnterpriseID: entID,
	}

	if refreshToken != "" {
		if err := h.cfg.Upstream.RefreshToken(a); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"ok": false, "status": "error", "message": "ExchangeToken 失败: " + err.Error(),
			})
			return
		}
	} else if a.AccessToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok": false, "status": "error", "message": "回调缺少 refreshToken，且 userJwt 也没有 Token",
		})
		return
	}

	// GetUserInfo 确认（失败不阻塞）
	if gu, gn, ge, gerr := h.cfg.Upstream.GetUserInfo(a); gerr == nil {
		if gu != "" {
			a.UID = gu
		}
		if gn != "" {
			a.Nickname = gn
		}
		if ge != "" {
			a.EnterpriseID = ge
		}
	}
	if a.UID == "" {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok": false, "status": "error", "message": "未能获取 uid，请检查回调链接是否完整",
		})
		return
	}

	if err := os.MkdirAll(h.cfg.AuthDir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok": false, "status": "error", "message": "创建 auth_dir 失败: " + err.Error(),
		})
		return
	}
	a.FilePath = filepath.Join(h.cfg.AuthDir, "trae-"+a.UID+".json")
	if err := a.SaveAtomic(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok": false, "status": "error", "message": "落盘失败: " + err.Error(),
		})
		return
	}
	h.cfg.Pool.Add(a)

	// 非阻塞签到 + 刷积分
	go func(authCopy *auth.Auth) {
		checkedIn, _, enable, serr := h.cfg.Upstream.CheckinStatus(authCopy)
		if serr == nil && !checkedIn && enable {
			_ = h.cfg.Upstream.CheckinClaim(authCopy)
		}
		if remain, err := h.cfg.Upstream.UserEntUsage(authCopy); err == nil {
			h.cfg.Pool.ReenableIfCredits(authCopy.UID, remain)
		}
	}(a)

	h.oauth.del(req.SessionID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"status":  "done",
		"message": fmt.Sprintf("登录成功：%s (%s)", nonempty(a.Nickname, "未命名"), shortID(a.UID)),
		"account": map[string]any{
			"uid":      a.UID,
			"nickname": a.Nickname,
		},
	})
}

// adminOAuthPoll 兼容 WorkBuddy 面板的 poll 调用；TRAE 无服务端轮询，始终提示粘贴回调。
func (h *Handler) adminOAuthPoll(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"status":  "pending",
		"message": "TRAE 需粘贴回调链接，请使用「提交回调」",
		"flow":    "callback_paste",
	})
}

func parseTraeCallback(callback string) (refreshToken string, userInfo, userJWT map[string]any, err error) {
	callback = strings.TrimSpace(callback)
	// 用户可能只贴 query 部分
	if !strings.Contains(callback, "://") && strings.Contains(callback, "=") {
		callback = "http://127.0.0.1/?" + strings.TrimPrefix(callback, "?")
	}
	u, perr := url.Parse(callback)
	if perr != nil {
		return "", nil, nil, perr
	}
	q := u.Query()
	refreshToken = q.Get("refreshToken")
	userInfo = parseJSONParam(q.Get("userInfo"))
	userJWT = parseJSONParam(q.Get("userJwt"))
	if refreshToken == "" && len(userInfo) == 0 && len(userJWT) == 0 {
		return "", nil, nil, fmt.Errorf("未找到 refreshToken / userInfo / userJwt 参数")
	}
	return refreshToken, userInfo, userJWT, nil
}

func parseJSONParam(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	for _, val := range []string{raw, mustUnquote(raw)} {
		var obj map[string]any
		if json.Unmarshal([]byte(val), &obj) == nil {
			return obj
		}
	}
	return nil
}

func mustUnquote(s string) string {
	u, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return u
}

func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

func nonempty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func shortID(u string) string {
	if len(u) <= 12 {
		return u
	}
	return u[:8] + "…"
}
