
GO_SRC := $(shell find -type f -name '*.go' ! -path '*/vendor/*')
VERSION ?= $(shell git describe --long --dirty)

all: style vet test dns-config

# Simple go build
dns-config: $(GO_SRC)
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags "-extldflags '-static' -X main.Version=$(VERSION)" -o dns-config .

vet:
	go vet

# Check code conforms to go fmt
style:
	! gofmt -s -l $(GO_SRC) 2>&1 | read 2>/dev/null

test:
	go test -v -covermode=count -coverprofile=cover.out

# Format the code
fmt:
	gofmt -s -w $(GO_SRC)

examples-docker-image: dns-config
	cp -f dns-config examples/dns-config
	docker build --build-arg=http_proxy=$(http_proxy) -t wrouesnel/dns-config-examples examples

run-examples: examples-docker-image
	docker run -it --net=none --dns=127.0.0.1 wrouesnel/dns-config-examples

.PHONY: test vet run-examples examples-docker-image
