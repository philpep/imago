all: build
.PHONY: all

build: main.go
	go build
.PHONY: build

docker:
	docker build --pull -t philpep/imago .
.PHONY: docker
