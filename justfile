test:
    go test -shuffle on -race -count 2 -v ./...

build:
    goreleaser build --snapshot --clean
