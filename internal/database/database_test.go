package database

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"aegis-waf/internal/config"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestOpenSQLiteMemory(t *testing.T) {
	db, err := Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer Close(db)

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate returned error: %v", err)
	}

	if !db.Migrator().HasTable(&Site{}) {
		t.Fatal("expected sites table")
	}
	if !db.Migrator().HasTable(&AccessLog{}) {
		t.Fatal("expected access_logs table")
	}
	if !db.Migrator().HasTable(&AttackLog{}) {
		t.Fatal("expected attack_logs table")
	}
}

func TestOpenSQLiteCreatesParentDirectory(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "nested", "aegis-waf.db")
	db, err := Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer Close(db)

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate returned error: %v", err)
	}
}

func TestOpenRejectsInvalidDriver(t *testing.T) {
	_, err := Open(config.DatabaseConfig{Driver: "oracle", DSN: "dsn"})
	if err == nil {
		t.Fatal("expected invalid driver error")
	}
	if !strings.Contains(err.Error(), "unsupported database driver") {
		t.Fatalf("expected clear driver error, got %v", err)
	}
}

func TestAutoMigrateRejectsNilDB(t *testing.T) {
	if err := AutoMigrate(nil); err == nil {
		t.Fatal("expected nil db error")
	}
}

func TestCloseNilDB(t *testing.T) {
	if err := Close(nil); err != nil {
		t.Fatalf("expected nil close to succeed, got %v", err)
	}
}

func TestOpenRejectsEmptyDSN(t *testing.T) {
	_, err := Open(config.DatabaseConfig{Driver: "sqlite", DSN: ""})
	if err == nil {
		t.Fatal("expected empty dsn error")
	}
}

func TestOpenPostgresRequiresDSN(t *testing.T) {
	_, err := Open(config.DatabaseConfig{Driver: "postgres", DSN: ""})
	if err == nil {
		t.Fatal("expected postgres empty dsn error")
	}
}

func TestOpenNormalizesDriverCase(t *testing.T) {
	db, err := Open(config.DatabaseConfig{Driver: "SQLITE", DSN: "file::memory:?cache=shared"})
	if err != nil {
		t.Fatalf("expected case-insensitive driver support, got %v", err)
	}
	defer Close(db)
}

func TestSiteRepositoryPreservesExplicitFalseFlags(t *testing.T) {
	db, err := Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer Close(db)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate returned error: %v", err)
	}
	repo := NewSiteRepository(db)
	site := Site{Name: "plain", Upstream: "http://127.0.0.1:8080", WAFEnabled: true, CCProtection: false, SemanticProtection: false, BlockScoreThreshold: 5}
	if err := site.SetDomains([]string{"plain.local"}); err != nil {
		t.Fatalf("SetDomains: %v", err)
	}
	if err := repo.Create(context.Background(), &site); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.Get(context.Background(), site.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CCProtection || got.SemanticProtection || !got.WAFEnabled {
		t.Fatalf("boolean flags not preserved: %#v", got)
	}
}

func TestAutoMigrateSeedsDisabledDefaultCCPolicies(t *testing.T) {
	db, err := Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file:" + t.Name() + "?mode=memory&cache=shared"})
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer Close(db)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate returned error: %v", err)
	}
	var policies []CCPolicy
	if err := db.Order("priority asc, id asc").Find(&policies).Error; err != nil {
		t.Fatalf("query cc policies: %v", err)
	}
	if len(policies) != 4 {
		t.Fatalf("default cc policies = %d, want 4", len(policies))
	}
	for _, policy := range policies {
		if policy.Enabled {
			t.Fatalf("default cc policy %q should be disabled", policy.Name)
		}
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("second AutoMigrate returned error: %v", err)
	}
	var count int64
	if err := db.Model(&CCPolicy{}).Count(&count).Error; err != nil {
		t.Fatalf("count cc policies: %v", err)
	}
	if count != 4 {
		t.Fatalf("cc policy seed should be idempotent, got %d", count)
	}
}

func TestAutoMigrateAllowsCreatingSiteWithLegacyDomainColumn(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open legacy sqlite: %v", err)
	}
	defer Close(db)
	if err := db.Exec(`CREATE TABLE sites (
		id integer primary key autoincrement,
		name text not null,
		domain text not null,
		domains_json text not null,
		upstream text not null,
		listen_port integer not null default 80,
		status text not null default 'enabled',
		tls_mode text not null default 'off',
		certificate_id integer default 0,
		certificate_name text,
		waf_enabled numeric not null,
		cc_protection numeric not null,
		semantic_protection numeric not null,
		policy_mode text not null default 'standard',
		block_score_threshold integer not null default 5,
		rule_groups_json text,
		created_at integer,
		updated_at integer
	)`).Error; err != nil {
		t.Fatalf("create legacy sites table: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate returned error: %v", err)
	}
	repo := NewSiteRepository(db)
	site := Site{Name: "legacy", Upstream: "http://127.0.0.1:8080", WAFEnabled: true, CCProtection: true, SemanticProtection: true, BlockScoreThreshold: 5}
	if err := site.SetDomains([]string{"legacy.local"}); err != nil {
		t.Fatalf("SetDomains: %v", err)
	}
	if err := repo.Create(context.Background(), &site); err != nil {
		t.Fatalf("Create with legacy domain column: %v", err)
	}
}
