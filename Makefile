GO ?= go
DIST ?= dist
BINARY ?= sroiaaa-agent

.PHONY: test run fmt build-linux-amd64 build-linux-arm64 build-linux-all docker-build docker-up fitness eval-models eval-zabbix eval-pegasus eval-headtohead

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

# Evaluations need live credentials exported into the environment, which the
# runtime env file provides:  source ~/.config/sroiaaa/env
eval-models:
	python3 ./scripts/eval_models.py

eval-zabbix:
	python3 ./scripts/eval_zabbix.py

eval-pegasus:
	python3 ./scripts/eval_pegasus.py

eval-headtohead:
	python3 ./scripts/eval_headtohead.py
