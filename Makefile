BINARY=blindspot
VERSION=$(shell git describe --tags --abbrev=0)
# VERSION HERE USE LATEST TAG

.PHONY: build build-win build-linux

# -H windowsgui builds a GUI-subsystem binary so double-clicking launches the tray
# without a console window. CLI use still works: main.go calls AttachToParentConsole
# when launched from an existing terminal.
build-win:
	GOOS=windows GOARCH=amd64 go build -ldflags="-H windowsgui -X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY).exe .

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="-X github.com/neozmmv/blindspot/cmd.Version=$(VERSION)" -o dist/$(BINARY)-linux-arm64 .

build: build-win build-linux