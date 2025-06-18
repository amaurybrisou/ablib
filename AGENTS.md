# Agent Instructions

This repository contains a Go module intended as a reusable library for other projects. All contributions must follow Go best practices and industry standards.

## Makefile targets
- `make lint` runs `golangci-lint` across the codebase.
- `make test` executes the Go test suite with race detection and verbose output.
- `make coverage` generates `coverage.html` using `go test -coverprofile` and should report nearly 100% coverage.

## Guidelines
- Tests must avoid custom mocks. Use `gomock` with `//go:generate` directives to create mocks.
- Keep package structure clear and idiomatic.
- Ensure `golangci-lint` passes and coverage stays high.
