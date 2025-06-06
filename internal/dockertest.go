package internal

import (
	"context"
	"fmt"
	"io"

	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
)

type Container struct {
	*dockertest.Pool
	*dockertest.Resource
}

type ContainerConfig struct {
	Repository string
	Tag        string
	Env        []string
	Cmd        []string
}

type poolConfig struct {
	Addr *string
	Pool *dockertest.Pool
}

type newContainerOption func(o *dockertest.RunOptions)

// NewContainer creates a new postgres container with the given configuration.
func NewContainer(poolconfig *poolConfig, config ContainerConfig, opts ...newContainerOption) (*Container, error) { //nolint:revive
	if poolconfig == nil || poolconfig.Addr == nil {
		poolconfig = &poolConfig{
			Addr: pointer(""),
		}
	}

	var pool *dockertest.Pool
	if poolconfig.Pool != nil {
		pool = poolconfig.Pool
	} else if poolconfig.Addr != nil {
		var err error
		pool, err = dockertest.NewPool(*poolconfig.Addr)
		if err != nil {
			return nil, fmt.Errorf("failed creating pool | %w", err)
		}
	}

	runOptions := &dockertest.RunOptions{
		Repository: config.Repository,
		Tag:        config.Tag,
		Env:        config.Env,
		Cmd:        config.Cmd,
	}

	for _, o := range opts {
		o(runOptions)
	}

	r, err := pool.RunWithOptions(runOptions)
	if err != nil {
		return nil, err
	}

	r.Expire(60 * 5) // 5 minutes

	return &Container{
		Pool:     pool,
		Resource: r,
	}, nil
}

func pointer(s string) *string {
	return &s
}

func (c *Container) TailLogs(ctx context.Context, wr io.Writer, follow bool) error {
	opts := docker.LogsOptions{
		Context: ctx,

		Stderr:      true,
		Stdout:      true,
		Follow:      follow,
		Timestamps:  true,
		RawTerminal: true,

		Container: c.Container.ID,

		OutputStream: wr,
	}

	return c.Client.Logs(opts)
}

func (c *Container) GetPort(port string) string {
	if c.Resource == nil {
		return ""
	}

	return c.Resource.GetPort(port)
}

func (c *Container) GetPortInt16() int16 {
	if c.Resource == nil {
		return 0
	}

	port := c.Resource.GetPort("27017/tcp")
	if port == "" {
		return 0
	}

	var p int64
	fmt.Sscanf(port, "%d", &p)
	return int16(p)
}

func (c *Container) Retry(fn func() error) error {
	if c.Resource == nil {
		return fmt.Errorf("container resource is nil")
	}

	return c.Pool.Retry(fn)
}

func (c *Container) Purge() error {
	if c.Resource == nil {
		return fmt.Errorf("container resource is nil")
	}

	if err := c.Pool.Purge(c.Resource); err != nil {
		return fmt.Errorf("failed to purge container | %w", err)
	}

	return nil
}
