package auditlog

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
	"aegis-waf/internal/detection"
	"aegis-waf/internal/pipeline"

	"gorm.io/gorm"
)

func TestQueuedWriterFlushesAccessAndAttackLogs(t *testing.T) {
	db := testDB(t)
	writer := NewQueuedWriter(db, 8, 2, 10*time.Millisecond)

	if err := writer.WriteAccess(context.Background(), database.AccessLog{RequestID: "a1", Method: "GET", Path: "/", Status: 200, Decision: "allow"}); err != nil {
		t.Fatalf("WriteAccess: %v", err)
	}
	if err := writer.WriteAttack(context.Background(), database.AttackLog{RequestID: "x1", Method: "GET", Path: "/x", StatusCode: 403, Action: "block", Stage: "detection"}); err != nil {
		t.Fatalf("WriteAttack: %v", err)
	}
	if err := writer.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	var accessCount int64
	var attackCount int64
	if err := db.Model(&database.AccessLog{}).Count(&accessCount).Error; err != nil {
		t.Fatalf("count access: %v", err)
	}
	if err := db.Model(&database.AttackLog{}).Count(&attackCount).Error; err != nil {
		t.Fatalf("count attack: %v", err)
	}
	if accessCount != 1 || attackCount != 1 {
		t.Fatalf("counts access=%d attack=%d", accessCount, attackCount)
	}
}

func TestQueuedWriterDropsAccessWhenQueueFull(t *testing.T) {
	db := testDB(t)
	writer := NewQueuedWriter(db, 1, 100, time.Hour)
	for i := 0; i < 100; i++ {
		_ = writer.WriteAccess(context.Background(), database.AccessLog{RequestID: fmt.Sprintf("a-%d", i), Method: "GET", Path: "/", Status: 200, Decision: "allow"})
	}
	if writer.Stats().DroppedAccess == 0 {
		t.Fatal("expected dropped access logs when queue is full")
	}
	_ = writer.Stop(context.Background())
}

func TestQueuedWriterDoesNotDropAttackWhenQueueFull(t *testing.T) {
	db := testDB(t)
	writer := NewQueuedWriter(db, 1, 100, time.Hour)
	for i := 0; i < 20; i++ {
		_ = writer.WriteAttack(context.Background(), database.AttackLog{RequestID: fmt.Sprintf("x-%d", i), Method: "GET", Path: "/x", StatusCode: 403, Action: "block", Stage: "detection"})
	}
	if err := writer.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var attackCount int64
	if err := db.Model(&database.AttackLog{}).Count(&attackCount).Error; err != nil {
		t.Fatalf("count attack: %v", err)
	}
	if attackCount != 20 {
		t.Fatalf("attackCount=%d, want 20", attackCount)
	}
}

func TestT137AttackLogScoreBreakdown(t *testing.T) {
	log := AttackLogFrom(nil, pipeline.Request{}, pipeline.Result{
		Decision:       pipeline.DecisionBlock,
		FinalAction:    pipeline.DecisionBlock,
		ScoreThreshold: 7,
		Detection: detection.Result{
			Score: 8,
			Matches: []detection.MatchedRule{
				{ID: 942100, Group: "sqli", Severity: "critical", Score: 5, Message: "sqli"},
				{ID: 941100, Group: "xss", Severity: "medium", Score: 3, Message: "xss"},
			},
		},
	}, 403, 0)

	if log.FinalAction != "block" {
		t.Fatalf("FinalAction=%q, want block", log.FinalAction)
	}

	var breakdown struct {
		TotalScore int `json:"totalScore"`
		Threshold  int `json:"threshold"`
		Rules      []struct {
			ID    int    `json:"id"`
			Group string `json:"group"`
			Score int    `json:"score"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(log.ScoreBreakdown), &breakdown); err != nil {
		t.Fatalf("ScoreBreakdown json: %v", err)
	}
	if breakdown.TotalScore != 8 || breakdown.Threshold != 7 {
		t.Fatalf("score breakdown totalScore=%d threshold=%d, want 8 and 7", breakdown.TotalScore, breakdown.Threshold)
	}
	if len(breakdown.Rules) != 2 {
		t.Fatalf("rules len=%d, want 2", len(breakdown.Rules))
	}
	wantRules := []struct {
		id    int
		group string
		score int
	}{
		{id: 942100, group: "sqli", score: 5},
		{id: 941100, group: "xss", score: 3},
	}
	for i, want := range wantRules {
		if breakdown.Rules[i].ID != want.id || breakdown.Rules[i].Group != want.group || breakdown.Rules[i].Score != want.score {
			t.Fatalf("rule[%d]=%+v, want id=%d group=%s score=%d", i, breakdown.Rules[i], want.id, want.group, want.score)
		}
	}
}

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.Open(config.DatabaseConfig{Driver: "sqlite", DSN: t.TempDir() + "/auditlog-test.db"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := database.AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	t.Cleanup(func() { _ = database.Close(db) })
	return db
}
