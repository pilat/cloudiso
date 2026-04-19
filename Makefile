GOLANGCI_LINT_VERSION := v2.6.2
GOLANGCI_LINT_PATH := $(HOME)/.local/bin/golangci-lint-$(subst v,,$(GOLANGCI_LINT_VERSION))
COVERAGE_PROFILE := /tmp/cloudiso-coverage.out

# Linker flags for macOS compatibility with Go < 1.24 (LC_UUID issue)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LDFLAGS := -ldflags="-linkmode=external"
endif

.PHONY: lint tests coverage all

all: fmt lint tests

tests:
	@echo "===> Running tests"
	go test $(LDFLAGS) -v -count=1 ./...

coverage:
	@echo "===> Running tests with coverage"
	go test $(LDFLAGS) -v -coverprofile=$(COVERAGE_PROFILE) -covermode=atomic ./...
	@echo ""
	@echo "===> Coverage report"
	go tool cover -func=$(COVERAGE_PROFILE)

$(GOLANGCI_LINT_PATH):
	@echo "===> Installing golangci-lint $(GOLANGCI_LINT_VERSION)"
	@mkdir -p $(HOME)/.local/bin
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b /tmp $(GOLANGCI_LINT_VERSION)
	@mv /tmp/golangci-lint $(GOLANGCI_LINT_PATH)

lint: $(GOLANGCI_LINT_PATH)
	@echo "===> Running lint"
	@$(GOLANGCI_LINT_PATH) run

fmt: $(GOLANGCI_LINT_PATH)
	@echo "===> Running fmt"
	@$(GOLANGCI_LINT_PATH) fmt
