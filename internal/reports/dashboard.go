package reports

import (
	"context"
	"time"

	"aegis-waf/internal/database"

	"gorm.io/gorm"
)

type Overview struct {
	RequestsToday    int64
	BlockedToday     int64
	AverageLatencyMS float64
}

type Store struct {
	db  *gorm.DB
	now func() time.Time
}

func NewStore(db *gorm.DB) *Store { return &Store{db: db, now: time.Now} }
func (s *Store) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *Store) Overview(ctx context.Context) (Overview, error) {
	if s == nil || s.db == nil {
		return Overview{}, nil
	}
	start := startOfDayMillis(s.now())
	var out Overview
	if err := s.db.WithContext(ctx).Model(&database.AccessLog{}).Where("created_at >= ?", start).Count(&out.RequestsToday).Error; err != nil {
		return out, err
	}
	if err := s.db.WithContext(ctx).Model(&database.AttackLog{}).Where("created_at >= ?", start).Count(&out.BlockedToday).Error; err != nil {
		return out, err
	}
	_ = s.db.WithContext(ctx).Model(&database.AccessLog{}).Where("created_at >= ?", start).Select("COALESCE(AVG(latency_ms), 0)").Scan(&out.AverageLatencyMS).Error
	return out, nil
}

func (s *Store) AttackLogs(ctx context.Context, limit int) ([]database.AttackLog, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var logs []database.AttackLog
	if err := s.db.WithContext(ctx).Order("created_at desc, id desc").Limit(limit).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

func startOfDayMillis(t time.Time) int64 {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location()).UnixMilli()
}
