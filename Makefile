export TZ := UTC
export LC_ALL := C.UTF-8

GOIMPORTS   := go tool goimports
STATICCHECK := go tool staticcheck
ERRCHECK    := go tool errcheck
GOVULNCHECK := go tool govulncheck

.PHONY: all check lint test cover fmt fmt-check vet staticcheck errcheck vulncheck reuse clean

all: check test

check: fmt-check vet staticcheck errcheck

lint: check vulncheck

test:
	CGO_ENABLED=1 go test -race -count=1 ./...

cover:
	CGO_ENABLED=1 go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

fmt:
	$(GOIMPORTS) -w .

fmt-check:
	@test -z "$$($(GOIMPORTS) -l .)" || { \
		echo "goimports would reformat:"; \
		$(GOIMPORTS) -l .; \
		exit 1; \
	}

vet:
	go vet ./...

staticcheck:
	$(STATICCHECK) ./...

errcheck:
	$(ERRCHECK) -ignoretests ./...

vulncheck:
	$(GOVULNCHECK) ./...

reuse:
	reuse --no-multiprocessing lint

clean:
	rm -f coverage.out
