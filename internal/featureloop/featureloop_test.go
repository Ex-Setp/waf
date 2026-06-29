package featureloop

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis-waf/internal/dataplane"
	"aegis-waf/internal/semantic/skeleton"
)

func testSkeleton(t *testing.T) *skeleton.ASTSkeleton {
	t.Helper()
	fp, err := skeleton.ParseSQL("SELECT username, password FROM users UNION SELECT credit_card, cvv FROM payments")
	if err != nil {
		t.Fatalf("ParseSQL returned error: %v", err)
	}
	return fp
}

func TestTranslateToCorazaRuleDeterministic(t *testing.T) {
	fp := testSkeleton(t)

	first, err := TranslateToCorazaRule(fp, RuleOptions{Message: "SQLi user's probe"})
	if err != nil {
		t.Fatalf("TranslateToCorazaRule returned error: %v", err)
	}
	second, err := TranslateToCorazaRule(fp, RuleOptions{Message: "SQLi user's probe"})
	if err != nil {
		t.Fatalf("TranslateToCorazaRule returned error: %v", err)
	}

	if first.RuleText != second.RuleText || first.FileName != second.FileName || first.RuleID != second.RuleID {
		t.Fatalf("expected deterministic output:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if !strings.Contains(first.RuleText, "SecRule ARGS") || !strings.Contains(first.RuleText, "@contains "+fp.Hash) {
		t.Fatalf("rule text missing fingerprint match: %s", first.RuleText)
	}
	if !strings.Contains(first.RuleText, "deny,status:403") {
		t.Fatalf("deny rule missing blocking action: %s", first.RuleText)
	}
	if !strings.Contains(first.RuleText, `msg:'SQLi user\'s probe'`) {
		t.Fatalf("message was not escaped: %s", first.RuleText)
	}
	if first.Fingerprint.Action != 1 || first.Fingerprint.Severity != 90 {
		t.Fatalf("unexpected fingerprint metadata: %+v", first.Fingerprint)
	}
}

func TestTranslateForGreyValidationUsesLogAction(t *testing.T) {
	rule, err := TranslateForGreyValidation(testSkeleton(t), RuleOptions{})
	if err != nil {
		t.Fatalf("TranslateForGreyValidation returned error: %v", err)
	}
	if rule.Action != RuleActionLog {
		t.Fatalf("expected log action, got %s", rule.Action)
	}
	if strings.Contains(rule.RuleText, "deny") || strings.Contains(rule.RuleText, "status:403") {
		t.Fatalf("grey validation rule should not block: %s", rule.RuleText)
	}
}

func TestRuleDeployerWritesAtomicallyCompatibleConf(t *testing.T) {
	dir := t.TempDir()
	rule, err := TranslateToCorazaRule(testSkeleton(t), RuleOptions{})
	if err != nil {
		t.Fatalf("TranslateToCorazaRule returned error: %v", err)
	}

	path, err := (RuleDeployer{Directory: dir}).Deploy(context.Background(), rule)
	if err != nil {
		t.Fatalf("Deploy returned error: %v", err)
	}
	if filepath.Ext(path) != ".conf" {
		t.Fatalf("expected .conf file, got %s", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(content) != rule.RuleText {
		t.Fatalf("unexpected deployed content: %q", content)
	}
}

type recordingSink struct {
	upserts []dataplane.SemanticFingerprint
	deletes []string
}

func (s *recordingSink) UpsertSemanticFingerprint(_ context.Context, fp dataplane.SemanticFingerprint) error {
	s.upserts = append(s.upserts, fp)
	return nil
}

func (s *recordingSink) DeleteSemanticFingerprint(_ context.Context, hash string) error {
	s.deletes = append(s.deletes, hash)
	return nil
}

func TestMapSyncerUpsertDelete(t *testing.T) {
	sink := &recordingSink{}
	rule, err := TranslateToCorazaRule(testSkeleton(t), RuleOptions{Action: RuleActionPass})
	if err != nil {
		t.Fatalf("TranslateToCorazaRule returned error: %v", err)
	}
	syncer := MapSyncer{Sink: sink}

	if err := syncer.Upsert(context.Background(), rule); err != nil {
		t.Fatalf("Upsert returned error: %v", err)
	}
	if len(sink.upserts) != 1 || sink.upserts[0].Hash != rule.Hash || sink.upserts[0].Action != 0 {
		t.Fatalf("unexpected upsert: %+v", sink.upserts)
	}
	if err := syncer.Delete(context.Background(), rule.Hash); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if len(sink.deletes) != 1 || sink.deletes[0] != rule.Hash {
		t.Fatalf("unexpected delete: %+v", sink.deletes)
	}
}

func TestAutoRollbackThreshold(t *testing.T) {
	if (AutoRollback{TotalHits: 100, FalsePositives: 5}).ShouldRollback() {
		t.Fatal("5% false positives should not rollback")
	}
	if !(AutoRollback{TotalHits: 100, FalsePositives: 6}).ShouldRollback() {
		t.Fatal("above 5% false positives should rollback")
	}
	if !(AutoRollback{FalseRate: 0.051}).ShouldRollback() {
		t.Fatal("explicit false rate above threshold should rollback")
	}
}

type recordingDisabler struct {
	ids []int
}

func (d *recordingDisabler) DisableRule(id int) error {
	d.ids = append(d.ids, id)
	return nil
}

func TestRollbackControllerDisablesDeletesAndRemoves(t *testing.T) {
	dir := t.TempDir()
	rule, err := TranslateToCorazaRule(testSkeleton(t), RuleOptions{})
	if err != nil {
		t.Fatalf("TranslateToCorazaRule returned error: %v", err)
	}
	deployer := RuleDeployer{Directory: dir}
	path, err := deployer.Deploy(context.Background(), rule)
	if err != nil {
		t.Fatalf("Deploy returned error: %v", err)
	}
	sink := &recordingSink{}
	disabler := &recordingDisabler{}
	controller := RollbackController{RuleDisabler: disabler, MapSyncer: MapSyncer{Sink: sink}, Deployer: deployer}

	result, err := controller.Evaluate(context.Background(), rule, AutoRollback{TotalHits: 10, FalsePositives: 1})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if !result.RolledBack || !result.Disabled || !result.MapDeleted || !result.RuleRemoved {
		t.Fatalf("unexpected rollback result: %+v", result)
	}
	if len(disabler.ids) != 1 || disabler.ids[0] != rule.RuleID {
		t.Fatalf("unexpected disabled rules: %+v", disabler.ids)
	}
	if len(sink.deletes) != 1 || sink.deletes[0] != rule.Hash {
		t.Fatalf("unexpected map deletes: %+v", sink.deletes)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected deployed rule removed, stat err=%v", err)
	}
}

func TestGreyControllerDeploysObservationRule(t *testing.T) {
	sink := &recordingSink{}
	controller := GreyController{
		Deployer:          RuleDeployer{Directory: t.TempDir()},
		MapSyncer:         MapSyncer{Sink: sink},
		ObservationWindow: time.Hour,
	}

	rule, path, err := controller.Deploy(context.Background(), testSkeleton(t))
	if err != nil {
		t.Fatalf("Deploy returned error: %v", err)
	}
	if path == "" || rule.Action != RuleActionLog {
		t.Fatalf("unexpected grey deploy result: rule=%+v path=%s", rule, path)
	}
	if len(sink.upserts) != 1 || sink.upserts[0].ExpiresAt.IsZero() {
		t.Fatalf("expected expiring map upsert, got %+v", sink.upserts)
	}
}
