package database

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

func migrateLegacySitesTable(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("sites") {
		return nil
	}
	columns, err := db.Migrator().ColumnTypes("sites")
	if err != nil {
		return fmt.Errorf("inspect sites table: %w", err)
	}
	var hasLegacyDomain bool
	var domainRequired bool
	for _, column := range columns {
		if !strings.EqualFold(column.Name(), "domain") {
			continue
		}
		hasLegacyDomain = true
		nullable, ok := column.Nullable()
		domainRequired = !ok || !nullable
		break
	}
	if !hasLegacyDomain || !domainRequired {
		return nil
	}
	return migrateLegacySitesTableSQLite(db)
}

func seedDefaultCCPolicies(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	var count int64
	if err := db.Model(&CCPolicy{}).Count(&count).Error; err != nil {
		return fmt.Errorf("count cc policies: %w", err)
	}
	if count > 0 {
		return nil
	}
	policies := []CCPolicy{
		{Name: "默认站点限速模板", Scope: "site", Threshold: 120, WindowSeconds: 60, Action: CCActionObserve + ">" + CCActionCaptcha + ">" + CCActionTempBlock, Priority: 100, Enabled: false},
		{Name: "默认路径限速模板", Scope: "path", Threshold: 60, WindowSeconds: 60, Action: CCActionCaptcha, Priority: 110, Enabled: false},
		{Name: "默认 404 扫描模板", Scope: "404", Threshold: 30, WindowSeconds: 60, Action: CCActionBlock, Priority: 120, Enabled: false},
		{Name: "默认登录失败模板", Scope: "login-failure:/login", Threshold: 5, WindowSeconds: 300, Action: CCActionCaptcha + ">" + CCActionTempBlock, Priority: 90, Enabled: false},
	}
	if err := db.Select("Name", "Scope", "Threshold", "WindowSeconds", "Action", "Priority", "Enabled").Create(&policies).Error; err != nil {
		return fmt.Errorf("seed default cc policies: %w", err)
	}
	names := make([]string, 0, len(policies))
	for _, policy := range policies {
		names = append(names, policy.Name)
	}
	if err := db.Model(&CCPolicy{}).Where("name IN ?", names).Update("enabled", false).Error; err != nil {
		return fmt.Errorf("disable default cc policies: %w", err)
	}
	return nil
}

func migrateLegacySitesTableSQLite(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`CREATE TABLE sites_new (
			id integer primary key autoincrement,
			name text not null,
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
			return fmt.Errorf("create migrated sites table: %w", err)
		}
		if err := tx.Exec(`INSERT INTO sites_new (
			id, name, domains_json, upstream, listen_port, status, tls_mode, certificate_id, certificate_name,
			waf_enabled, cc_protection, semantic_protection, policy_mode, block_score_threshold,
			rule_groups_json, created_at, updated_at
		) SELECT
			id, name,
			CASE
				WHEN domains_json IS NOT NULL AND domains_json != '' AND domains_json != 'null' THEN domains_json
				WHEN domain IS NOT NULL AND domain != '' THEN json_array(domain)
				ELSE '[]'
			END,
			upstream, listen_port, status, tls_mode, certificate_id, certificate_name,
			waf_enabled, cc_protection, semantic_protection, policy_mode, block_score_threshold,
			rule_groups_json, created_at, updated_at
		FROM sites`).Error; err != nil {
			return fmt.Errorf("copy migrated sites rows: %w", err)
		}
		if err := tx.Exec(`DROP TABLE sites`).Error; err != nil {
			return fmt.Errorf("drop legacy sites table: %w", err)
		}
		if err := tx.Exec(`ALTER TABLE sites_new RENAME TO sites`).Error; err != nil {
			return fmt.Errorf("rename migrated sites table: %w", err)
		}
		return nil
	})
}
