//go:build !windows

package detection

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func WatchSIGHUP(ctx context.Context, reload func(context.Context) error, onError func(error), onReload func()) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-signals:
				if err := reload(ctx); err != nil {
					if onError != nil {
						onError(err)
					}
					continue
				}
				if onReload != nil {
					onReload()
				}
			}
		}
	}()
	return func() { close(done) }
}
