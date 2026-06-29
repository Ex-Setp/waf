//go:build windows

package detection

import "context"

func WatchSIGHUP(context.Context, func(context.Context) error, func(error), func()) func() {
	return func() {}
}
