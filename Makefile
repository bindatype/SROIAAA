GO ?= go
DIST ?= dist
BINARY ?= sroiaaa-agent

.PHONY: test run fmt build-linux-amd64 build-linux-arm64 build-linux-all docker-build docker-up fitness

test:
	$(GO) test ./...

run:
	$(GO) run ./cmd/sroiaaa-agent

fmt:
	$(GO) fmt ./...

build-linux-amd64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o $(DIST)/$(BINARY)-linux-amd64 ./cmd/sroiaaa-agent

build-linux-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -o $(DIST)/$(BINARY)-linux-arm64 ./cmd/sroiaaa-agent

build-linux-all: build-linux-amd64 build-linux-arm64

docker-build:
	docker build -t sroiaaa:phase1 .

docker-up:
	docker compose up --build

fitness:
	sh ./scripts/harness_fitness.sh
