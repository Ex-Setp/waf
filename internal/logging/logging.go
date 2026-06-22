package logging

import (
	"fmt"
	"strings"

	"aegis-waf/internal/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New builds a Zap logger from the application logging configuration.
func New(cfg config.LoggingConfig) (*zap.Logger, error) {
	zapCfg, err := buildConfig(cfg)
	if err != nil {
		return nil, err
	}

	return zapCfg.Build()
}

// NewSugared builds a SugaredLogger from the application logging configuration.
func NewSugared(cfg config.LoggingConfig) (*zap.SugaredLogger, error) {
	logger, err := New(cfg)
	if err != nil {
		return nil, err
	}

	return logger.Sugar(), nil
}

func buildConfig(cfg config.LoggingConfig) (zap.Config, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return zap.Config{}, err
	}

	format, err := parseFormat(cfg.Format)
	if err != nil {
		return zap.Config{}, err
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.LowercaseLevelEncoder

	return zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		Development:       false,
		Encoding:          format,
		EncoderConfig:     encoderCfg,
		OutputPaths:       []string{"stdout"},
		ErrorOutputPaths:  []string{"stderr"},
		DisableStacktrace: true,
	}, nil
}

func parseLevel(value string) (zapcore.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("invalid logging level %q: expected debug, info, warn, or error", value)
	}
}

func parseFormat(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "json":
		return "json", nil
	case "console":
		return "console", nil
	default:
		return "", fmt.Errorf("invalid logging format %q: expected json or console", value)
	}
}
