package detection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	manager  *Manager
	watcher  *fsnotify.Watcher
	done     chan struct{}
	onError  func(error)
	onReload func()
	once     sync.Once
}

func NewWatcher(manager *Manager, onReload func(), onError func(error)) (*Watcher, error) {
	if manager == nil {
		return nil, errors.New("rules manager is required")
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &Watcher{manager: manager, watcher: watcher, done: make(chan struct{}), onReload: onReload, onError: onError}
	if err := w.addPaths(); err != nil {
		_ = watcher.Close()
		return nil, err
	}
	return w, nil
}

func (w *Watcher) Start(ctx context.Context) {
	go w.loop(ctx)
}

func (w *Watcher) Stop() error {
	w.once.Do(func() {
		close(w.done)
	})
	return w.watcher.Close()
}

func (w *Watcher) loop(ctx context.Context) {
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if shouldReload(event) {
				if timer == nil {
					timer = time.NewTimer(100 * time.Millisecond)
					timerC = timer.C
				} else {
					timer.Reset(100 * time.Millisecond)
				}
			}
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.report(err)
		case <-timerC:
			if err := w.manager.Reload(ctx); err != nil {
				w.report(err)
			} else if w.onReload != nil {
				w.onReload()
			}
			timerC = nil
		}
	}
}

func (w *Watcher) addPaths() error {
	if w.manager.directory != "" {
		if err := os.MkdirAll(w.manager.directory, 0o755); err != nil {
			return err
		}
		if err := w.watcher.Add(w.manager.directory); err != nil {
			return err
		}
	}
	for _, file := range w.manager.customFiles {
		dir := filepath.Dir(file)
		if dir == "." || dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := w.watcher.Add(dir); err != nil {
			return err
		}
	}
	return nil
}

func (w *Watcher) report(err error) {
	if w.onError != nil {
		w.onError(err)
	}
}

func shouldReload(event fsnotify.Event) bool {
	if event.Name == "" {
		return false
	}
	ext := filepath.Ext(event.Name)
	if ext != ".conf" && ext != ".rule" {
		return false
	}
	return event.Has(fsnotify.Create) || event.Has(fsnotify.Write) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)
}
