LDFLAGS = -s -w
GOFLAGS = -trimpath -ldflags "$(LDFLAGS)"

all: release

.PHONY: release
release:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/ki-keyring-windows-amd64.exe $(GOFLAGS)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/ki-keyring-linux-amd64 $(GOFLAGS)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/ki-keyring-darwin-arm64 $(GOFLAGS)

.PHONY: clean
clean:
	rm -rf bin
