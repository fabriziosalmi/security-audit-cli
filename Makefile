# sec-audit developer Makefile.
VERSION     ?= 0.1.0
LDFLAGS     := -s -w
INSTALL_BIN := $(HOME)/.local/bin/sec-audit

.PHONY: help build test vet bench fuzz install clean

help:
	@echo "Targets:"
	@echo "  build    - compile sec-audit binary (with ad-hoc codesign on Darwin)"
	@echo "  test     - run go vet and go test -race -cover ./..."
	@echo "  vet      - run go vet ./..."
	@echo "  bench    - run all deterministic benchmarks with memory allocation stats"
	@echo "  fuzz     - run FuzzValidateFindingsBytes for 5 seconds"
	@echo "  install  - build and atomically install binary into $(INSTALL_BIN)"
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
	go test -fuzz=FuzzValidateFindingsBytes -fuzztime=5s ./internal/validator

install: build
	@mkdir -p $(dir $(INSTALL_BIN))
	rm -f $(INSTALL_BIN)
	install -m 0755 sec-audit $(INSTALL_BIN)
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign --sign - --force --timestamp=none $(INSTALL_BIN) 2>&1 | grep -v "replacing existing" || true; \
	fi
	@echo "Installed sec-audit ($(VERSION)) at $(INSTALL_BIN)"

clean:
	rm -f sec-audit sec-audit.exe *.test *.out coverage.txt coverage.html
	rm -rf dist/
