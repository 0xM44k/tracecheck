//go:build !linux && !windows

package watch

import (
	"context"
	"errors"
)

// Run is not implemented on this platform.
func Run(ctx context.Context, o Options) error {
	return errors.New("watch is implemented for linux and windows only")
}
