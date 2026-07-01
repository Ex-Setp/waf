package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aegis-waf/internal/config"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

func Open(cfg config.DatabaseConfig) (*gorm.DB, error) {
	driver := strings.ToLower(strings.TrimSpace(cfg.Driver))
	if driver == "" {
		return nil, fmt.Errorf("database driver is required")
	}
	switch driver {
	case DriverSQLite:
		return openSQLite(cfg.DSN)
	case DriverPostgres:
		return openPostgres(cfg.DSN)
	default:
		return nil, fmt.Errorf("unsupported database driver %q: expected sqlite or postgres", cfg.Driver)
	}
}

func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}
	if err := migrateLegacySitesTable(db); err != nil {
		return err
	}
	if err := db.AutoMigrate(&Site{}, &Certificate{}, &SemanticFingerprint{}, &AccessLog{}, &AttackLog{}, &AccessRule{}, &CCPolicy{}, &ProtectionRule{}, &ProtectionRulePublishSnapshot{}, &SiteProtectionPolicy{}, &PolicyVersion{}, &PolicyAudit{}, &AuditEvent{}); err != nil {
		return err
	}
	return seedDefaultCCPolicies(db)
}

func Close(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func openSQLite(dsn string) (*gorm.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("sqlite database dsn is required")
	}
	if err := ensureSQLiteParentDir(dsn); err != nil {
		return nil, err
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	return db, nil
}

func ensureSQLiteParentDir(dsn string) error {
	trimmed := strings.TrimSpace(dsn)
	if strings.HasPrefix(trimmed, "file:") || trimmed == ":memory:" {
		return nil
	}
	dir := filepath.Dir(trimmed)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create sqlite database directory: %w", err)
	}
	return nil
}

func openPostgres(dsn string) (*gorm.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("postgres database dsn is required")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open postgres database: %w", err)
	}
	return db, nil
}
