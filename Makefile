BINARY=blindspot
VERSION=$(shell git describe --tags --abbrev=0)
# VERSION HERE USE LATEST TAG

.PHONY: build build-win build-linux

# Two Windows binaries: the console-subsystem CLI (blindspot.exe) behaves like a
# normal command-line tool from a terminal, and the GUI-subsystem tray
# (blindspot-tray.exe, -H windowsgui) launches without ever opening a console. The
# tray shells out to the CLI sitting next to it, so ship them in the same folder.
build-win:
	GOOS=windows GOARCH=amd64 go build -ldflags="-X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY).exe .
	GOOS=windows GOARCH=amd64 go build -ldflags="-H windowsgui -X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY)-tray.exe ./cmd/tray

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="-X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY)-linux-arm64 .

build: build-win build-linux