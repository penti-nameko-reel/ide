.PHONY: build run
build:
	go build -o bin/idp ./cmd/idp
run:
	go run ./cmd/idp
