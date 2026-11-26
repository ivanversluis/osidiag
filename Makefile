.PHONY: build test lint security clean
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/osidiag ./cmd/osidiag
test:
	go test -race ./...
lint:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
security:
	govulncheck ./...
	gosec -exclude=G115,G204,G304,G402 ./...
clean:
	rm -rf bin dist
