# sec-audit developer Makefile.
VERSION     ?= 0.1.3
LDFLAGS     := -s -w -X main.Version=$(VERSION)
INSTALL_BIN := $(HOME)/.local/bin/sec-audit

.PHONY: help build test vet bench fuzz install vsix clean

help:
	@echo "Targets:"
	@echo "  build    - compile sec-audit binary (with ad-hoc codesign on Darwin)"
	@echo "  test     - run go vet and go test -race -cover ./..."
	@echo "  vet      - run go vet ./..."
	@echo "  bench    - run all deterministic benchmarks with memory allocation stats"
	@echo "  fuzz     - run all 4 fuzz targets for 3 seconds each"
	@echo "  install  - build and atomically install binary into $(INSTALL_BIN)"
	@echo "  vsix     - package deterministic VS Code extension (.vsix) into dist/"
	@echo "  clean    - remove local build and coverage artifacts"

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o sec-audit ./cmd/sec-audit
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign --sign - --force --timestamp=none sec-audit 2>&1 | grep -v "replacing existing" || true; \
	fi

vet:
	go vet ./...

test:
	go vet ./... && go test -count=1 -race -cover -timeout 120s ./...

bench:
	go test -bench=. -benchmem ./internal/validator ./internal/engine

fuzz:
	go test -fuzz=FuzzValidateFindingsBytes -fuzztime=3s ./internal/validator
	go test -fuzz=FuzzValidateCoverageLedgerBytes -fuzztime=3s ./internal/validator
	go test -fuzz=FuzzValidateJSONPreflight -fuzztime=3s ./internal/validator
	go test -fuzz=FuzzDeriveCoverageID -fuzztime=3s ./internal/validator

install: build
	@mkdir -p $(dir $(INSTALL_BIN))
	rm -f $(INSTALL_BIN)
	install -m 0755 sec-audit $(INSTALL_BIN)
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign --sign - --force --timestamp=none $(INSTALL_BIN) 2>&1 | grep -v "replacing existing" || true; \
	fi
	@echo "Installed sec-audit ($(VERSION)) at $(INSTALL_BIN)"

vsix:
	go run ./editors/vscode/pack -dir editors/vscode -out dist/sec-audit-vscode-$(VERSION).vsix

clean:
	rm -f sec-audit sec-audit.exe *.test *.out coverage.txt coverage.html
	rm -rf dist/
