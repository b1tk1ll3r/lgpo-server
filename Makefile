VERSION ?= dev
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: test build clean

test:
	go test ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gpo-server ./cmd/server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gpoctl ./cmd/gpoctl
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gpo-agent-windows-amd64.exe ./cmd/agent
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/gpoctl-windows-amd64.exe ./cmd/gpoctl

clean:
	rm -rf bin
