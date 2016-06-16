
GO_SRC := $(shell find -type f -name "*.go")

all: vet test dns-config

# Simple go build
dns-config: $(GO_SRC)
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags "-extldflags '-static' -X main.Version=$(shell git describe --long --dirty)" -o dns-config .

vet:
	go vet .

test:
	go test -v .

examples-docker-image: dns-config
	cp -f dns-config examples/dns-config
	docker build --build-arg=http_proxy=$(http_proxy) -t wrouesnel/dns-config-examples examples

run-examples: examples-docker-image
	docker run -it --net=none --dns=127.0.0.1 wrouesnel/dns-config-examples

.PHONY: test vet run-examples examples-docker-image
