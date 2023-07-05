.PHONY: test
test:
	@go test -count=1 -timeout 3m -v ./...

.PHONY: lint
lint:
	golangci-lint run ./...