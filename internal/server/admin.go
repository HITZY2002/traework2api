package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"traework2api/internal/auth"
	"traework2api/internal/pool"
	"traework2api/internal/upstream"
)

// adminOverview 面板总览。
func (h *Handler) adminOverview(w http.ResponseWriter, r *http.Request) {
	total, healthy, disabled, cooling, credits := h.cfg.Pool.Stats()
	models := h.modelList()
	ids := make([]map[string]any, 0, len(models))
	for _, m := range models {
		ids = append(ids, map[string]any{"id": m["id"]})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "traework2api",
		"region":  "cn",
		"stats": map[string]any{
			"total":    total,
			"healthy":  healthy,
			"disabled": disabled,
			"cooling":  cooling,
			"credits":  credits,
		},
		"accounts": h.cfg.Pool.List(),
		"models":   ids,
		"schedule": map[string]any{
			"checkin_hours":   h.cfg.CheckinHours,
			"keepalive_hours": h.cfg.KeepaliveHours,
		},
	})
}

type uidBody struct {
	UID    string `json:"uid"`
	Reason string `json:"reason"`
}

func readUIDBody(r *http.Request) (uidBody, error) {
	var b uidBody
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return b, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return b, nil
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, err
	}
	return b, nil
}

type actionResult struct {
	UID     string `json:"uid"`
	OK      bool   `json:"ok"`
	Credits int64  `json:"credits,omitempty"`
	Message string `json:"message,omitempty"`
}

func (h *Handler) adminCredits(w http.ResponseWriter, r *http.Request) {
	body, err := readUIDBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "bad json: " + err.Error()})
		return
	}
	targets := h.pickTargets(body.UID, false)
	results := make([]actionResult, 0, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for _, st := range targets {
		st := st
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := h.refreshOneCredits(st.UID)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}()
	}
	wg.Wait()
	okAll := true
	for _, r := range results {
		if !r.OK {
			okAll = false
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      okAll,
		"message": summaryMsg("积分刷新", results),
		"results": results,
	})
}

func (h *Handler) adminCheckin(w http.ResponseWriter, r *http.Request) {
	body, err := readUIDBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "bad json: " + err.Error()})
		return
	}
	targets := h.pickTargets(body.UID, true) // 冷却中也签到
	results := make([]actionResult, 0, len(targets))
	for _, st := range targets {
		a := h.cfg.Pool.AuthByUID(st.UID)
		if a == nil || a.RefreshTokenValue() == "" {
			results = append(results, actionResult{UID: st.UID, OK: false, Message: "no auth"})
			continue
		}
		// token 临近过期先刷
		if a.NeedsRefresh(2 * time.Hour) {
			if err := h.cfg.Upstream.RefreshToken(a); err != nil {
				results = append(results, actionResult{UID: st.UID, OK: false, Message: "refresh: " + err.Error()})
				continue
			}
			_ = a.SaveAtomic()
		}
		msg := "ok"
		checkedIn, _, enable, serr := h.cfg.Upstream.CheckinStatus(a)
		switch {
		case serr != nil:
			if isAlreadyCheckedIn(serr.Error()) {
				msg = "already checked in"
			} else {
				msg = serr.Error()
			}
		case checkedIn:
			msg = "already checked in"
		case !enable:
			msg = "checkin disabled"
		default:
			if err := h.cfg.Upstream.CheckinClaim(a); err != nil {
				if isAlreadyCheckedIn(err.Error()) {
					msg = "already checked in"
				} else {
					msg = err.Error()
				}
			} else {
				msg = "checked in"
			}
		}
		remain, err := h.cfg.Upstream.UserEntUsage(a)
		if err != nil {
			results = append(results, actionResult{UID: st.UID, OK: false, Message: "checkin=" + msg + "; credits=" + err.Error()})
			continue
		}
		h.cfg.Pool.ReenableIfCredits(st.UID, remain)
		ok := msg == "checked in" || msg == "already checked in" || msg == "ok"
		results = append(results, actionResult{UID: st.UID, OK: ok, Credits: remain, Message: msg})
	}
	okAll := true
	for _, r := range results {
		if !r.OK {
			okAll = false
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      okAll,
		"message": summaryMsg("签到", results),
		"results": results,
	})
}

func isAlreadyCheckedIn(msg string) bool {
	s := strings.ToLower(msg)
	return strings.Contains(s, "已签到") ||
		strings.Contains(s, "already check") ||
		strings.Contains(s, "already checked")
}

func (h *Handler) adminKeepalive(w http.ResponseWriter, r *http.Request) {
	body, err := readUIDBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "bad json: " + err.Error()})
		return
	}
	if body.UID == "" && h.cfg.Scheduler != nil {
		h.cfg.Scheduler.RunRefreshNow()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "保活已触发（全员 token 预刷新）"})
		return
	}
	targets := h.pickTargets(body.UID, false)
	results := make([]actionResult, 0, len(targets))
	for _, st := range targets {
		a := h.cfg.Pool.AuthByUID(st.UID)
		if a == nil || a.RefreshTokenValue() == "" {
			results = append(results, actionResult{UID: st.UID, OK: false, Message: "no auth"})
			continue
		}
		if err := h.cfg.Upstream.RefreshToken(a); err != nil {
			var ue *upstream.Error
			if errors.As(err, &ue) && ue.Kind == upstream.ErrSessionDead {
				h.cfg.Pool.Disable(st.UID, "session dead")
			}
			results = append(results, actionResult{UID: st.UID, OK: false, Message: err.Error()})
			continue
		}
		_ = a.SaveAtomic()
		results = append(results, actionResult{UID: st.UID, OK: true, Message: "refreshed"})
	}
	okAll := true
	for _, r := range results {
		if !r.OK {
			okAll = false
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      okAll,
		"message": summaryMsg("保活", results),
		"results": results,
	})
}

func (h *Handler) adminReload(w http.ResponseWriter, r *http.Request) {
	if h.cfg.AuthDir == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "auth_dir 未配置"})
		return
	}
	auths, err := auth.LoadDir(h.cfg.AuthDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	h.cfg.Pool.SyncToDir(auths)
	total, healthy, _, _, _ := h.cfg.Pool.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "已重载 auths",
		"loaded":  len(auths),
		"total":   total,
		"healthy": healthy,
	})
}

func (h *Handler) adminEnable(w http.ResponseWriter, r *http.Request) {
	body, err := readUIDBody(r)
	if err != nil || body.UID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "uid required"})
		return
	}
	if !h.cfg.Pool.Enable(body.UID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "account not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "已启用 " + body.UID})
}

func (h *Handler) adminDisable(w http.ResponseWriter, r *http.Request) {
	body, err := readUIDBody(r)
	if err != nil || body.UID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "uid required"})
		return
	}
	reason := body.Reason
	if reason == "" {
		reason = "manual disable"
	}
	if _, ok := h.cfg.Pool.Status(body.UID); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "account not found"})
		return
	}
	h.cfg.Pool.Disable(body.UID, reason)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "已禁用 " + body.UID})
}

func (h *Handler) adminClearCooldown(w http.ResponseWriter, r *http.Request) {
	body, err := readUIDBody(r)
	if err != nil || body.UID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "uid required"})
		return
	}
	if !h.cfg.Pool.ClearCooldown(body.UID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "account not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "已清冷却 " + body.UID})
}

func (h *Handler) pickTargets(uid string, includeCooling bool) []pool.Status {
	if uid != "" {
		st, ok := h.cfg.Pool.Status(uid)
		if !ok {
			return nil
		}
		return []pool.Status{st}
	}
	out := make([]pool.Status, 0)
	for _, st := range h.cfg.Pool.List() {
		if st.Disabled {
			continue
		}
		if st.Cooling && !includeCooling {
			continue
		}
		out = append(out, st)
	}
	return out
}

func (h *Handler) refreshOneCredits(uid string) actionResult {
	a := h.cfg.Pool.AuthByUID(uid)
	if a == nil {
		return actionResult{UID: uid, OK: false, Message: "no auth"}
	}
	// token 临近过期先刷
	if a.NeedsRefresh(2 * time.Hour) {
		if err := h.cfg.Upstream.RefreshToken(a); err != nil {
			return actionResult{UID: uid, OK: false, Message: "refresh: " + err.Error()}
		}
		_ = a.SaveAtomic()
	}
	remain, err := h.cfg.Upstream.UserEntUsage(a)
	if err != nil {
		return actionResult{UID: uid, OK: false, Message: err.Error()}
	}
	h.cfg.Pool.SetCredits(uid, remain)
	if remain > 0 {
		h.cfg.Pool.ReenableIfCredits(uid, remain)
	}
	return actionResult{UID: uid, OK: true, Credits: remain, Message: "ok"}
}

func summaryMsg(action string, results []actionResult) string {
	if len(results) == 0 {
		return action + ": 无目标账号"
	}
	ok, fail := 0, 0
	for _, r := range results {
		if r.OK {
			ok++
		} else {
			fail++
		}
	}
	if fail == 0 {
		return action + "完成: " + itoa(ok) + " 成功"
	}
	return action + "完成: " + itoa(ok) + " 成功 / " + itoa(fail) + " 失败"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
