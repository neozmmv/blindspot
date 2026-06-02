BINARY="blindspot"

.PHONY: build build-win

build-win:
	GOOS=windows GOARCH=amd64 go build -o dist/$(BINARY).exe .

build-linux:
	GOOS=linux GOARCH=amd64 go build -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o dist/$(BINARY)-linux-arm64 .
	
build: build-win build-linux