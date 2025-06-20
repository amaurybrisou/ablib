package ablib

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type startFuncType func(context.Context) (<-chan struct{}, <-chan error)
type stopFuncType func(context.Context) error

type Core struct {
	startFuncs []startFuncType
	stopFuncs  []stopFuncType
	cleanup    func()
}

func (c *Core) AddStartFunc(s startFuncType) {
	c.startFuncs = append(c.startFuncs, s)
}

func (c *Core) AddStopFunc(s stopFuncType) {
	c.stopFuncs = append(c.stopFuncs, s)
}

func NewCore(opts ...Options) *Core {
	c := &Core{}

	for _, o := range opts {
		o.New(c)
	}

	return c
}

func hasServiceStarted(ctx context.Context, expectedStart int, startedChans <-chan <-chan struct{}) <-chan struct{} {
	startChan := aggChan(ctx, startedChans)
	done := make(chan struct{}, 1)

	go func() {
		defer close(done)
		for expectedStart > 0 {
			select {
			case <-ctx.Done():
				return
			case <-startChan:
				expectedStart--
			default:
				time.Sleep(time.Second)
				log.Ctx(ctx).Debug().Msg("waiting to start")
			}
		}
		done <- struct{}{}
	}()

	return done
}

func hasServiceErrors(ctx context.Context, errChans <-chan <-chan error) <-chan error {
	errChan := aggChan(ctx, errChans)
	errorEncountered := make(chan error, 1)

	go func() {
		defer close(errorEncountered)
		for {
			select {
			case err, ok := <-errChan:
				if !ok {
					return
				}
				if err != nil {
					errorEncountered <- err // Forward the error
					return
				}
			case <-ctx.Done():
				err := ctx.Err()
				if errors.Is(err, context.Canceled) {
					return
				}
				errorEncountered <- err
				return
			}
		}
	}()

	return errorEncountered
}

func (c *Core) Start(ctx context.Context) (<-chan struct{}, <-chan error) {
	log.Ctx(ctx).Info().Msg("starting backend")
	if len(c.startFuncs) == 0 {
		errChan := make(chan error, 1) // Initialize error channel with capacity of 1
		errChan <- ErrNoService        // Directly send the error
		close(errChan)                 // Close the channel after sending the error
		return nil, errChan
	}

	startedChans := make(chan (<-chan struct{}), len(c.startFuncs))
	errChans := make(chan (<-chan error))

	allStarted := hasServiceStarted(ctx, len(c.startFuncs), startedChans)
	hasErrorChan := hasServiceErrors(ctx, errChans)

	for _, sf := range c.startFuncs {
		go func(f startFuncType) {
			started, err := f(ctx)
			errChans <- err
			startedChans <- started
		}(sf)
	}

	c.cleanup = func() {
		close(startedChans)
		close(errChans)
	}

	return allStarted, hasErrorChan
}

func (c *Core) Shutdown(ctx context.Context) <-chan error {
	log.Ctx(ctx).Debug().Msg("shutting down")
	errChan := make(chan error, len(c.stopFuncs))
	wg := sync.WaitGroup{}

	for _, fn := range c.stopFuncs {
		wg.Add(1)
		go func(f stopFuncType) {
			defer wg.Done()
			if err := f(ctx); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("closing service")
				errChan <- err
			}
		}(fn)
	}

	// Close error channel after all goroutines complete
	go func() {
		wg.Wait()
		if c.cleanup != nil {
			c.cleanup()
		}
		close(errChan)
	}()

	return errChan
}

var (
	ErrSignalReceived = errors.New("signal received")
	ErrNoService      = errors.New("core must be started with at least one service")
)

func aggChan[T any](ctx context.Context, chans <-chan (<-chan T)) <-chan T {
	var wg sync.WaitGroup

	outputChan := make(chan T)
	out := func(cc <-chan T) {
		defer wg.Done()
		select {
		case c, ok := <-cc: // cc must be closed explicitly by its creator.
			if ok {
				outputChan <- c // Forward received channel data
			}
		case <-ctx.Done():
			return
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case s, ok := <-chans:
				if !ok {
					return
				}
				wg.Add(1)
				go out(s)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(outputChan)
	}()

	return outputChan
}
