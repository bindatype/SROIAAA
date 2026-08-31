GO ?= go
DIST ?= dist
BINARY ?= sroiaaa-agent

.PHONY: help install test run fmt build-linux-amd64 build-linux-arm64 build-linux-all docker-build docker-up fitness eval-models eval-zabbix eval-pegasus eval-headtohead eval-ablate eval-prompt-ab eval-lead probe

# Default target: say what exists. A bare `make` that silently builds one
# thing tells a newcomer nothing about the other fifteen.
help:
	@echo 'Setup and checks:'
	@echo '  make test              unit tests; no credentials, no network'
	@echo '  make install           link scripts/ask into ~/bin so you can ask from anywhere'
	@echo '  make fmt               gofmt the tree'
	@echo ''
	@echo 'These need:  source ~/.config/sroiaaa/env'
	@echo '  make probe             ask the Zabbix trap questions and judge them by eye'
	@echo '  make eval-zabbix       grade the Zabbix path end to end'
	@echo '  make eval-pegasus      grade model-authored SQL'
	@echo '  make eval-headtohead   compare two models over six question shapes'
	@echo '  make eval-prompt-ab    compare two prompts on the same binary'
	@echo '  make eval-lead         measure the lead-with-the-failure rule alone'
	@echo '  make eval-ablate       which prompt rules this model needs'
	@echo '  make eval-models       intent routing across several models'
	@echo ''
	@echo 'Reports are written to runtime/*.md and printed to stdout.'

# Puts `ask` on your PATH. It is a symlink rather than a copy, so it cannot go
# stale the way a hand-placed binary in ~/bin did -- that one was two days and
# four connector changes behind the source when it was noticed.
install:
	@mkdir -p $(HOME)/bin
	@ln -sf $(CURDIR)/scripts/ask $(HOME)/bin/ask
	@echo 'linked $(HOME)/bin/ask -> $(CURDIR)/scripts/ask'
	@case ":$$PATH:" in *":$(HOME)/bin:"*) ;; \
	  *) echo 'NOTE: $(HOME)/bin is not on your PATH; add it in ~/.bashrc' ;; esac
	@echo 'try:  ask "how many agents are disconnected right now?"'

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
#
# Each one prints to stdout AND writes runtime/<name>.md. If you go looking for
# the results afterwards, that is where they are -- with a .md suffix, which is
# why `find . -name eval-zabbix` finds nothing.
eval-models:
	python3 ./scripts/eval_models.py

eval-zabbix:
	python3 ./scripts/eval_zabbix.py

eval-pegasus:
	python3 ./scripts/eval_pegasus.py

eval-headtohead:
	python3 ./scripts/eval_headtohead.py

eval-ablate:
	python3 ./scripts/eval_ablate.py

eval-prompt-ab:
	python3 ./scripts/eval_prompt_ab.py

eval-lead:
	python3 ./scripts/eval_lead.py

# Not an evaluation: it prints answers and what a right and a wrong one look
# like, for a person to judge.
probe:
	sh ./scripts/zabbix-probe.sh
