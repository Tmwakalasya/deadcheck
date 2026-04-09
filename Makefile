BINARY := deadcheck

.PHONY: build test lint run

build:
	go build -o $(BINARY) ./cmd/deadcheck

test:
	go test ./...

lint:
	go vet ./...

run:
	go run ./cmd/deadcheck
