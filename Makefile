.PHONY: test
test:
	@go test -count=1 -race -timeout 3m -v ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: coverage
coverage:
	@go test -count=1 -race -timeout 3m -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"