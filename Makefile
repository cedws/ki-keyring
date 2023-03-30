LDFLAGS = -s -w
GOFLAGS = -trimpath -ldflags "$(LDFLAGS)"

define build
	mkdir -p bin
	CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build -o bin/pubkey-extract-$(1)-$(2) $(GOFLAGS)
endef

all: release

.PHONY: release
release:
	$(call build,windows,amd64)
	$(call build,linux,amd64)
	$(call build,darwin,arm64)

.PHONY: clean
clean:
	rm -rf bin
