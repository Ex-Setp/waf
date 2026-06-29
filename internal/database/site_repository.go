package database

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type SiteRepository struct{ db *gorm.DB }

func NewSiteRepository(db *gorm.DB) *SiteRepository { return &SiteRepository{db: db} }

func (r *SiteRepository) List(ctx context.Context) ([]Site, error) {
	var sites []Site
	if err := r.db.WithContext(ctx).Order("id asc").Find(&sites).Error; err != nil {
		return nil, err
	}
	return sites, nil
}

func (r *SiteRepository) Get(ctx context.Context, id uint) (Site, error) {
	var site Site
	if err := r.db.WithContext(ctx).First(&site, id).Error; err != nil {
		return Site{}, err
	}
	return site, nil
}

func (r *SiteRepository) Create(ctx context.Context, site *Site) error {
	if err := normalizeSite(site); err != nil {
		return err
	}
	return r.db.WithContext(ctx).Select("*").Create(site).Error
}

func (r *SiteRepository) Update(ctx context.Context, site *Site) error {
	if err := normalizeSite(site); err != nil {
		return err
	}
	return r.db.WithContext(ctx).Save(site).Error
}

func (r *SiteRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&Site{}, id).Error
}

func normalizeSite(site *Site) error {
	if site == nil {
		return fmt.Errorf("site is nil")
	}
	site.Name = strings.TrimSpace(site.Name)
	site.Upstream = strings.TrimSpace(site.Upstream)
	if site.Name == "" {
		return fmt.Errorf("site name is required")
	}
	if site.DomainsJSON == "" || len(site.Domains()) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	if site.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}
	if site.ListenPort == 0 {
		site.ListenPort = 80
	}
	if site.Status == "" {
		site.Status = SiteStatusEnabled
	}
	if site.TLSMode == "" {
		site.TLSMode = "off"
	}
	if site.RuleGroupsJSON == "" {
		if err := site.SetRuleGroups(nil); err != nil {
			return err
		}
	}
	return nil
}
