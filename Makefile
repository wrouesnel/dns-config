
GO_SRC := $(shell find -type f -name "*.go")

all: vet test dns-config

# Simple go build
dns-config: $(GO_SRC)
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags "-extldflags '-static' -X main.Version=$(shell git describe --long --dirty)" -o dns-config .

vet:
	go vet .

test:
	go test -v .

.PHONY: docker-build docker test vet
