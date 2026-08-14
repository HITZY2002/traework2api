package server

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed panel.html
var panelHTMLRaw string

// servePanel 提供管理控制台（账号池 / 签到 / 积分 / 授权登录）。
// 路由：GET /、/admin、/panel（无鉴权；页面自身用 localStorage 存 key 调 admin API）。
func (h *Handler) servePanel(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path != "/" && path != "/admin" && path != "/admin/" && path != "/panel" && path != "/panel/" {
		http.NotFound(w, r)
		return
	}
	html := panelHTMLRaw
	html = strings.ReplaceAll(html, "__SERVICE_NAME__", "traework2api")
	html = strings.ReplaceAll(html, "__SERVICE_TITLE__", "TraeWork2API")
	html = strings.ReplaceAll(html, "__LOGO__", "TW")
	html = strings.ReplaceAll(html, "__ACCENT__", "#2563eb")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}
