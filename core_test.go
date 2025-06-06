package ablib_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/amaurybrisou/ablib"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type CustomTestService struct {
	startErr bool
	stopErr  bool
	done     chan struct{}
}

var errCustomStart = errors.New("custom start error")
var errCustomStop = errors.New("custom stop error")

func (s CustomTestService) New(c *ablib.Core) {
	c.AddStartFunc(s.Start)
	c.AddStopFunc(s.Stop)
}

func (s CustomTestService) Start(_ context.Context) (<-chan struct{}, <-chan error) {
	errChan := make(chan error)
	startedChan := make(chan struct{})

	go func() {
		time.Sleep(time.Millisecond * 10)
		startedChan <- struct{}{}
	}()

	if s.startErr {
		go func() {
			time.Sleep(time.Millisecond * 10)
			errChan <- errCustomStart
		}()
	}

	return startedChan, errChan
}

func (s CustomTestService) Stop(_ context.Context) error {
	close(s.done)
	if s.stopErr {
		return errCustomStop
	}
	return nil
}

func TestCoreNoServiceError(t *testing.T) {
	lcore := ablib.NewCore()
	started, errChan := lcore.Start(context.Background())
	require.Nil(t, started)
	require.ErrorIs(t, <-errChan, ablib.ErrNoService)
}

func TestCoreError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	lcore := ablib.NewCore(CustomTestService{startErr: true, done: make(chan struct{})})
	started, errChan := lcore.Start(ctx)
	require.NotNil(t, started)
	<-started
	require.ErrorIs(t, <-errChan, errCustomStart)
}

func TestCoreContextDeadlineError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()
	lcore := ablib.NewCore(CustomTestService{done: make(chan struct{})})
	started, errChan := lcore.Start(ctx)
	require.NotNil(t, started)
	<-started
	require.ErrorIs(t, <-errChan, context.DeadlineExceeded)
}

func TestCoreShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	lcore := ablib.NewCore(CustomTestService{startErr: false, done: make(chan struct{})})
	started, _ := lcore.Start(ctx)
	require.NotNil(t, started)
	<-started
	err := lcore.Shutdown(ctx)
	require.NoError(t, <-err)
}

func TestCoreShutdownError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	lcore := ablib.NewCore(CustomTestService{startErr: false, stopErr: true, done: make(chan struct{})})
	started, _ := lcore.Start(ctx)
	require.NotNil(t, started)
	<-started
	errChan := lcore.Shutdown(ctx)
	require.ErrorIs(t, <-errChan, errCustomStop)
}

func TestCoreShutdownContextDeadlineError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	lcore := ablib.NewCore(CustomTestService{startErr: false, stopErr: true, done: make(chan struct{})})
	started, _ := lcore.Start(ctx)
	require.NotNil(t, started)
	<-started
	ctx, cancel = context.WithTimeout(context.Background(), 0)
	defer cancel()
	err := lcore.Shutdown(ctx)
	require.ErrorIs(t, <-err, errCustomStop)
}

func TestCoreServices(t *testing.T) {
	services := []func() ablib.Options{
		func() ablib.Options { return ablib.WithLogLevel(ablib.LookupEnv("LOG_LEVEL", "debug")) },
		func() ablib.Options {
			return ablib.WithHTTPServer(
				ablib.LookupEnv("HTTP_SERVER_ADDR", "0.0.0.0"),
				ablib.LookupEnvInt("HTTP_SERVER_PORT", 8089),
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }),
			)
		},
		ablib.WithSignals,
		func() ablib.Options {
			return ablib.WithPrometheus(
				ablib.LookupEnv("HTTP_PROM_ADDR", "0.0.0.0"),
				ablib.LookupEnvInt("HTTP_PROM_PORT", 2112),
			)
		},
		func() ablib.Options {
			return ablib.HeartBeat(
				ablib.WithRequestPath("/hc"),
				ablib.WithClientTimeout(5*time.Second),
				ablib.WithInterval(ablib.LookupEnvDuration("HEARTBEAT_INTERVAL", "10s")),
				ablib.WithErrorIncrement(ablib.LookupEnvDuration("HEARTBEAT_ERROR_INCREMENT", "5s")),
				ablib.WithFetchServiceFunction(func(ctx context.Context) ([]ablib.Service, error) {
					return nil, nil
				}),
				ablib.WithUpdateServiceStatusFunction(func(ctx context.Context, u uuid.UUID, s string) error {
					return nil
				}),
			)
		}}

	for i := range services {
		options := []ablib.Options{}
		for j := 0; j <= i; j++ {
			options = append(options, services[j]())
		}

		lcore := ablib.NewCore(options...)
		started, _ := lcore.Start(context.Background())
		require.NotNil(t, started)
		<-started
		errChan := lcore.Shutdown(context.Background())
		for err := range errChan {
			require.NoError(t, err)
		}

		options = []ablib.Options{}
		for j := 0; j <= i; j++ {
			options = append(options, services[j]())
		}
	}
}
