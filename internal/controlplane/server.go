package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	controlv1 "aegis-waf/api/control/v1"
	"aegis-waf/internal/config"

	"google.golang.org/grpc"
)

const healthStatusServing = "SERVING"

type Server struct {
	cfg     config.ControlConfig
	version string

	mu       sync.Mutex
	grpc     *grpc.Server
	listener net.Listener
	stopped  chan struct{}
}

func New(cfg config.ControlConfig, version string) *Server {
	return &Server{
		cfg:     cfg,
		version: version,
	}
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.grpc != nil {
		return fmt.Errorf("control plane already started")
	}

	network := strings.ToLower(strings.TrimSpace(s.cfg.Network))
	address := strings.TrimSpace(s.cfg.Address)
	if network == "" {
		return fmt.Errorf("control plane network is required")
	}
	if address == "" {
		return fmt.Errorf("control plane address is required")
	}

	listener, err := listen(network, address)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	controlv1.RegisterControlServiceServer(grpcServer, s)

	stopped := make(chan struct{})
	s.grpc = grpcServer
	s.listener = listener
	s.stopped = stopped

	go func() {
		defer close(stopped)
		if serveErr := grpcServer.Serve(listener); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			// Serve errors are returned to clients through connection failure; startup
			// errors happen before this goroutine is launched.
		}
	}()

	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	grpcServer := s.grpc
	stopped := s.stopped
	s.grpc = nil
	s.listener = nil
	s.stopped = nil
	s.mu.Unlock()

	if grpcServer == nil {
		return
	}

	grpcServer.GracefulStop()
	if stopped != nil {
		<-stopped
	}
}

func (s *Server) Health(context.Context, *controlv1.HealthRequest) (*controlv1.HealthResponse, error) {
	return &controlv1.HealthResponse{
		Status:  healthStatusServing,
		Version: s.version,
	}, nil
}

func listen(network, address string) (net.Listener, error) {
	switch network {
	case "unix":
		if err := prepareUnixSocket(address); err != nil {
			return nil, err
		}
	case "tcp":
	default:
		return nil, fmt.Errorf("unsupported control plane network %q: expected unix or tcp", network)
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, fmt.Errorf("listen control plane %s %s: %w", network, address, err)
	}

	return listener, nil
}

func prepareUnixSocket(address string) error {
	dir := filepath.Dir(address)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create control plane socket directory: %w", err)
		}
	}

	if err := os.Remove(address); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale control plane socket: %w", err)
	}

	return nil
}
