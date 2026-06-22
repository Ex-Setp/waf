package main

import (
"context"
"flag"
"fmt"
"os"
"os/signal"
"syscall"
"time"

"aegis-waf/internal/config"
"aegis-waf/internal/crs"
"aegis-waf/internal/database"
"aegis-waf/internal/dataplane"
"aegis-waf/internal/detection"
"aegis-waf/internal/httpserver"
"aegis-waf/internal/logging"
"aegis-waf/internal/pipeline"

"go.uber.org/zap"
)

const version = "0.1.0-t024"

func main() {
configPath := flag.String("config", "", "path to YAML configuration file")
flag.Parse()

cfg, err := config.Load(*configPath)
if err != nil {
fmt.Fprintf(os.Stderr, "load config: %v\n", err)
os.Exit(1)
}

logger, err := logging.New(cfg.Logging)
if err != nil {
fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
os.Exit(1)
}
defer func() {
_ = logger.Sync()
}()

db, err := database.Open(cfg.Database)
if err != nil {
logger.Error("init database failed", zap.Error(err))
os.Exit(1)
}
defer func() {
if closeErr := database.Close(db); closeErr != nil {
logger.Warn("close database failed", zap.Error(closeErr))
}
}()

if err := database.AutoMigrate(db); err != nil {
logger.Error("migrate database failed", zap.Error(err))
os.Exit(1)
}

customDetectionEngine, err := detection.NewManager(cfg.Rules.Directory, cfg.Rules.CustomFiles, cfg.Rules.DisabledRuleIDs, cfg.Rules.AutoReload)
if err != nil {
logger.Error("init detection engine failed", zap.Error(err))
os.Exit(1)
}
detectionEngine := detection.RuntimeRuleEngine(customDetectionEngine)
var crsManager *crs.Manager
if cfg.CRS.Enabled {
crsManager = crs.NewManager(crs.Config{Enabled: cfg.CRS.Enabled, RulesDir: cfg.CRS.RulesDir, ParanoiaLevel: cfg.CRS.ParanoiaLevel, InboundThreshold: cfg.CRS.InboundThreshold, OutboundThreshold: cfg.CRS.OutboundThreshold, RequestBodyLimit: cfg.CRS.RequestBodyLimit, AuditLogEnabled: cfg.CRS.AuditLogEnabled, FailOpen: cfg.CRS.FailOpen})
corazaEngine, crsErr := detection.NewCorazaEngine(crsManager)
if crsErr != nil {
logger.Error("init CRS detection engine failed", zap.Error(crsErr))
os.Exit(1)
}
detectionEngine = detection.NewCompositeEngine(corazaEngine, customDetectionEngine, cfg.CRS.FailOpen)
}
logger.Info("detection engine ready",
zap.String("rulesDirectory", cfg.Rules.Directory),
zap.Int("rulesLoaded", len(detectionEngine.Rules())),
zap.Bool("autoReload", cfg.Rules.AutoReload),
zap.Bool("crsEnabled", cfg.CRS.Enabled),
)

if cfg.Rules.AutoReload {
ruleWatcher, err := detection.NewWatcher(customDetectionEngine,
func() { logger.Info("rules reloaded", zap.Int("rulesLoaded", len(detectionEngine.Rules()))) },
func(reloadErr error) { logger.Warn("rules reload failed", zap.Error(reloadErr)) },
)
if err != nil {
logger.Error("start rules watcher failed", zap.Error(err))
os.Exit(1)
}
ruleWatcher.Start(context.Background())
defer func() {
if stopErr := ruleWatcher.Stop(); stopErr != nil {
logger.Warn("stop rules watcher failed", zap.Error(stopErr))
}
}()
}

stopSIGHUP := detection.WatchSIGHUP(context.Background(), detectionEngine.Reload,
func(reloadErr error) { logger.Warn("rules SIGHUP reload failed", zap.Error(reloadErr)) },
func() { logger.Info("rules reloaded by SIGHUP", zap.Int("rulesLoaded", len(detectionEngine.Rules()))) },
)
defer stopSIGHUP()

var dataplaneEngine dataplane.Engine
if cfg.Dataplane.Enabled {
dataplaneEngine, err = dataplane.New(cfg.Dataplane, logger)
if err != nil {
logger.Error("init dataplane failed", zap.Error(err))
os.Exit(1)
}
if err := dataplaneEngine.Start(context.Background()); err != nil {
logger.Error("start dataplane failed", zap.Error(err))
os.Exit(1)
}
defer func() {
if stopErr := dataplaneEngine.Stop(context.Background()); stopErr != nil {
logger.Warn("stop dataplane failed", zap.Error(stopErr))
}
}()
logger.Info("dataplane ready",
zap.String("mode", cfg.Dataplane.Mode),
zap.String("interface", cfg.Dataplane.InterfaceName),
zap.Bool("failOpen", cfg.Dataplane.FailOpen),
)
}

var semanticEngine detection.Engine
if cfg.Security.EnableSemantic {
semanticEngine = detection.NewSemanticEngine(nil, detection.SemanticOptions{})
logger.Info("semantic engine ready")
}

pipelineEngine := pipeline.New(
pipeline.Config{FailOpen: cfg.Dataplane.FailOpen},
pipeline.WithDataplane(dataplaneEngine),
pipeline.WithDetection(detectionEngine),
pipeline.WithSemantic(semanticEngine),
)
serverOptions := []httpserver.Option{httpserver.WithDatabase(db), httpserver.WithDetectionEngine(detectionEngine)}
if crsManager != nil {
serverOptions = append(serverOptions, httpserver.WithCRSManager(crsManager))
}
if fastBlocker, ok := dataplaneEngine.(dataplane.FastBlocker); ok {
serverOptions = append(serverOptions, httpserver.WithFastBlocker(fastBlocker))
}
server := httpserver.New(cfg.Server, cfg.Security, pipelineEngine, serverOptions...)

logger.Info(
"Aegis-WAF High Performance starting",
zap.String("version", version),
zap.String("host", cfg.Server.Host),
zap.Int("port", cfg.Server.Port),
zap.String("mode", cfg.Server.Mode),
)
logger.Info("database ready",
zap.String("driver", cfg.Database.Driver),
)
logger.Info("http server ready", zap.String("address", server.Addr()))
if server.HTTPSAddrEnabled() {
logger.Info("https server ready", zap.String("address", server.HTTPSAddr()), zap.Bool("acme", cfg.Server.TLS.ACME.Enabled))
}

serverErr := make(chan error, 1)
go func() { serverErr <- server.Start() }()

shutdown := make(chan os.Signal, 1)
signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
defer signal.Stop(shutdown)

select {
case err := <-serverErr:
if err != nil {
logger.Error("http server failed", zap.Error(err))
os.Exit(1)
}
case sig := <-shutdown:
logger.Info("shutdown requested", zap.String("signal", sig.String()))
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
if err := server.Stop(ctx); err != nil {
logger.Warn("stop http server failed", zap.Error(err))
}
if err := <-serverErr; err != nil {
logger.Warn("http server stopped with error", zap.Error(err))
}
}
}
