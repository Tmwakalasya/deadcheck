BINARY := deadcheck

.PHONY: build test lint run

build:
	go build -o $(BINARY) .

test:
	go test ./...

lint:
	go vet ./...

run:
	go run .
