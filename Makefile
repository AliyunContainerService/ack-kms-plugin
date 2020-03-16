##############################################################################################################
binary := kubernetes-kms
DOCKER_IMAGE := acs/ack-kms-plugin
METALINTER_CONCURRENCY ?= 4
METALINTER_DEADLINE ?= 180
VERSION          := v0.0.1
CGO_ENABLED_FLAG := 0

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

deps: setup
	@echo "Ensuring Dependencies..."
	$Q go env
	$Q dep ensure

clean:
	@echo "Clean..."
	$Q rm -rf $(binary)

setup: clean
	@echo "Setup..."
	go get -u github.com/golang/dep/cmd/dep

authors:
	$Q git log --all --format='%aN <%cE>' | sort -u  | sed -n '/github/!p' > GITAUTHORS
	$Q cat AUTHORS GITAUTHORS  | sort -u > NEWAUTHORS
	$Q mv NEWAUTHORS AUTHORS
	$Q rm -f NEWAUTHORS
	$Q rm -f GITAUTHORS

testint:
	@echo "Running Integration tests..."
	$Q sudo GOPATH=$(GOPATH) go test -v -count=1 gitlab.alibaba-inc.com/cos/ack-kms-plugin/tests/client

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
	go install ./main.go

	gometalinter --concurrency=$(METALINTER_CONCURRENCY) --deadline=$(METALINTER_DEADLINE)s ./... --vendor --linter='errcheck:errcheck:-ignore=net:Close' --cyclo-over=20 \
		--linter='vet:go vet --no-recurse -composites=false:PATH:LINE:MESSAGE' --disable=interfacer --dupl-threshold=50

check-all:
	go install ./main.go
	gometalinter --concurrency=$(METALINTER_CONCURRENCY) --deadline=600s ./... --vendor --cyclo-over=20 \
		--linter='vet:go vet --no-recurse:PATH:LINE:MESSAGE' --dupl-threshold=50
		--dupl-threshold=50

clean:
	rm -f $(BIN)