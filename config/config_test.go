package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTempEnvFile(t *testing.T, name string, content string) {
	t.Helper()
	err := os.WriteFile(name, []byte(content), 0600)
	require.NoError(t, err)
}

func cleanup(files ...string) {
	for _, f := range files {
		err := os.Remove(f)
		if err != nil && !os.IsNotExist(err) {
			panic(err)
		}
	}
}

func TestNew(t *testing.T) {
	t.Run("default values when no env file", func(t *testing.T) {
		cleanup(".env", ".env.test")

		cfg := New()

		assert.Equal(t, "info", cfg.LogLevel)
		assert.Equal(t, "0.0.0.0", cfg.BindAddr)
		assert.Equal(t, 8080, cfg.BindPort)
	})

	t.Run("load from .env file", func(t *testing.T) {
		cleanup(".env", ".env.test")
		createTempEnvFile(t, ".env", `
LOG_LEVEL=debug
BIND_ADDR=127.0.0.1
BIND_PORT=3000
`)
		defer cleanup(".env")

		cfg := New()

		assert.Equal(t, "debug", cfg.LogLevel)
		assert.Equal(t, "127.0.0.1", cfg.BindAddr)
		assert.Equal(t, 3000, cfg.BindPort)
	})

	t.Run("load from env specific file", func(t *testing.T) {
		cleanup(".env", ".env.test")
		createTempEnvFile(t, ".env", `LOG_LEVEL=info`)
		createTempEnvFile(t, ".env.test", `LOG_LEVEL=debug`)
		defer cleanup(".env", ".env.test")

		os.Setenv("ENV", "test") //nolint:errcheck,gosec
		defer os.Unsetenv("ENV") //nolint:errcheck,gosec

		cfg := New()

		assert.Equal(t, "debug", cfg.LogLevel)
	})

	t.Run("environment variables override file values", func(t *testing.T) {
		cleanup(".env", ".env.test")
		createTempEnvFile(t, ".env", `LOG_LEVEL=info`)
		defer cleanup(".env")

		os.Setenv("LOG_LEVEL", "trace") //nolint:errcheck,gosec
		os.Setenv("BIND_PORT", "9000")  //nolint:errcheck,gosec
		defer func() {
			os.Unsetenv("LOG_LEVEL") //nolint:errcheck,gosec
			os.Unsetenv("BIND_PORT") //nolint:errcheck,gosec
		}()

		cfg := New()

		assert.Equal(t, "trace", cfg.LogLevel)
		assert.Equal(t, 9000, cfg.BindPort)
	})

	t.Run("invalid env values", func(t *testing.T) {
		cleanup(".env", ".env.test")
		os.Setenv("BIND_PORT", "invalid") //nolint:errcheck,gosec
		defer os.Unsetenv("BIND_PORT")    //nolint:errcheck,gosec

		assert.Panics(t, func() {
			New()
		})
	})
}
