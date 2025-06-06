# ablib

A Go library providing common application building blocks and utilities for web services.

## Features

- **Core Application Framework**

  - Service lifecycle management (start/stop)
  - Graceful shutdown handling
  - Signal handling

- **Configuration**

  - Environment variable loading
  - Multiple environment support (.env, .env.test, etc)
  - Type-safe config parsing

- **HTTP Utilities**

  - Middleware (logging, auth, rate limiting)
  - JWT authentication
  - Cookie handling
  - Request logging

- **Monitoring**

  - Prometheus metrics integration
  - Health check endpoints
  - Heartbeat service

- **Database**

  - MongoDB client wrapper
  - Database migrations
  - Connection management

- **Logging**
  - Structured logging with zerolog
  - Console and JSON formats
  - Request/Response logging

## Installation

```sh
go get github.com/amaurybrisou/ablib
```

## Quick Start

```go
package main

import (
    "context"
    "net/http"
    "github.com/amaurybrisou/ablib"
)

func main() {
    core := ablib.NewCore(
        ablib.WithLogLevel("debug"),
        ablib.WithHTTPServer("0.0.0.0", 8080, helloHandler()),
    )

    started, _ := core.Start(context.Background())
    <-started // Wait for start

    // Graceful shutdown
    errChan := core.Shutdown(context.Background())
    for err := range errChan {
        // Handle shutdown errors
    }
}

func helloHandler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, World!"))
    }
}
```

## Detailed Usage

### HTTP Server with Middleware

```go
import (
    "github.com/amaurybrisou/ablib/http"
)

func main() {
    // Create a new core with HTTP server and middleware
    core := ablib.NewCore(
        ablib.WithHTTPServer("0.0.0.0", 8080,
            yourHandler(),
            http.Logger(logger),           // Request logging
            http.RateLimit(100, time.Minute), // Rate limiting
            http.JWT(secretKey),           // JWT authentication
        ),
    )
}
```

### Prometheus Metrics

```go
func main() {
    core := ablib.NewCore(
        // Expose metrics on port 2112
        ablib.WithPrometheus("0.0.0.0", 2112),
    )
}
```

### Heartbeat Service

```go
func main() {
    core := ablib.NewCore(
        ablib.WithHeartbeatAt([]string{"service1", "service2"},
            time.Second * 30,  // Check interval
            updateStatus,      // Status update function
        ),
    )
}
```

### Environment Configuration

```go
type Config struct {
    DatabaseURL string `env:"DATABASE_URL,required"`
    Port        int    `env:"PORT" default:"8080"`
}

func main() {
    var cfg Config
    if err := ablib.LoadEnv(&cfg); err != nil {
        log.Fatal(err)
    }
}
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Testing

Run the test suite:

```sh
make test
```

Generate coverage report:

```sh
make coverage
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
