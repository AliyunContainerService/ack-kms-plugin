##############################################################################################################
BINARY := ack-kms-plugin
DOCKER_IMAGE ?= acs/ack-kms-plugin
METALINTER_CONCURRENCY ?= 4
METALINTER_DEADLINE ?= 180
VERSION          ?= v0.0.1
CGO_ENABLED_FLAG ?= 0

ifeq ($(OS),Windows_NT)
	GOOS_FLAG = windows
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S), Linux)
		GOOS_FLAG = linux
	endif
	ifeq ($(UNAME_S), Darwin)
		GOOS_FLAG = darwin
	endif
endif

.PHONY: build
build:
	@echo "Building..."
	$Q GOOS=${GOOS_FLAG} CGO_ENABLED=${CGO_ENABLED_FLAG} go build .

build-image:
	@echo "Building docker image..."
	$Q docker build -t $(DOCKER_IMAGE):$(VERSION) .

.PHONY: clean deps test testint

deps:
	@echo "Ensuring Dependencies..."
	$Q go env
	$Q go mod download

clean:
	@echo "Clean..."
	$Q rm -rf $(BINARY)

setup: clean
	@echo "Setup..."

authors:
	$Q git log --all --format='%aN <%cE>' | sort -u  | sed -n '/github/!p' > GITAUTHORS
	$Q cat AUTHORS GITAUTHORS  | sort -u > NEWAUTHORS
	$Q mv NEWAUTHORS AUTHORS
	$Q rm -f NEWAUTHORS
	$Q rm -f GITAUTHORS

testint:
	@echo "Running Integration tests..."
	$Q go test -v -count=1 ./tests/client

test:
	@echo "Running Unit Tests..."
ifndef CI
	@echo "Running Unit Tests outside CI..."
	$Q go env
	go test -v -count=1 `go list ./... | grep -v client`
else
	@echo "Running Unit Tests inside CI..."
	go test -v `go list ./... | grep -v client`
endif

check:
	go build .

	# gometalinter is deprecated and does not support Go modules.
	# Replace with golangci-lint if linting is required in CI.
	# golangci-lint run ./...

check-all:
	go build .
