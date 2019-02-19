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
	for image in $$(grep 'FROM' Dockerfile | awk '{ print $$2 }'); do docker pull $$image; done
	docker build -t philpep/imago .
.PHONY: docker
