package main

import "testing"

func TestIsAlready(t *testing.T) {
	// 明确"已签到"标记 → true
	if !isAlready("今日已签到") {
		t.Error("已签到 should be true")
	}
	if !isAlready("you have already checked in") {
		t.Error("already checked in should be true")
	}
	// 歧义/错误路径 → false（不误判为已签）
	if isAlready("checkin service error") {
		t.Error("checkin service error should NOT be already")
	}
	if isAlready("upstream 429: checkin rate limited") {
		t.Error("429 rate limit should NOT be already")
	}
	if isAlready("code=400 bad request") {
		t.Error("code=400 should NOT be already (removed ambiguous marker)")
	}
	if isAlready("") {
		t.Error("empty should be false")
	}
}
