all: build
.PHONY: all

build: main.go
	go build
.PHONY: build

install: build
	go install
.PHONY: install

test:
	go test -v
.PHONY: test

check:
	errcheck ./...
	go fmt
	goimports -w .
.PHONY: check

docker:
	docker build --pull -t philpep/imago .
.PHONY: docker
