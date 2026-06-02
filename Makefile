BINARY=blindspot
VERSION=$(shell git describe --tags --abbrev=0)
# VERSION HERE USE LATEST TAG

.PHONY: build build-win build-linux

build-win:
	GOOS=windows GOARCH=amd64 go build -ldflags="-X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY).exe .

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="-X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY)-linux-arm64 .

build: build-win build-linux