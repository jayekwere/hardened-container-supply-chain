SHELL := /bin/bash
GO := .tools/bin/go
export GOTOOLCHAIN := local
export GOPROXY := off
export GOSUMDB := off
export GOCACHE := $(CURDIR)/.cache/go-build
export PATH := $(CURDIR)/.tools/bin:$(PATH)

.PHONY: tools test chart image reproduce integration scan check cluster
tools:
	python3 scripts/bootstrap.py
test:
	python3 scripts/check-inputs.py
	python3 scripts/test_image_gate.py
	test "$$($(GO) env GOVERSION)" = go1.27.3
	test -z "$$($(GO) list -mod=readonly -m all | tail -n +2)"
	test -z "$$(.tools/go/bin/gofmt -l cmd internal integration)"
	$(GO) vet ./...
	$(GO) test -race -count=1 -coverprofile=artifacts-coverage.tmp ./...
	@mkdir -p artifacts
	@mv artifacts-coverage.tmp artifacts/coverage.txt
chart:
	./scripts/chart.sh
image:
	./scripts/build.sh
reproduce:
	./scripts/reproduce.sh
integration:
	TEST_IMAGE=supply-demo:local $(GO) test -tags=integration -count=1 -v ./integration
scan:
	./scripts/scan.sh
check: test chart reproduce integration scan
cluster:
	./scripts/cluster.sh
