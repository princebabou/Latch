BINARY := latch
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE) -X main.builtBy=make

.PHONY: all build test vet conformance verify clean snapshot

all: verify build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)$(if $(findstring Windows_NT,$(OS)),.exe,) ./cmd/latch

test:
	go test ./...

vet:
	go vet ./...

conformance:
	go run ./cmd/latch conformance

verify: test vet conformance

snapshot:
	goreleaser release --snapshot --clean

clean:
	go clean
