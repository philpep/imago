FROM golang:1.11-alpine as builder
RUN apk add --no-cache git
RUN go get -d -v github.com/tools/godep
RUN go get -d -v k8s.io/client-go/...
RUN git -C /go/src/k8s.io/client-go checkout v10.0.0
RUN cd /go/src/github.com/tools/godep && go install
RUN cd /go/src/k8s.io/client-go && /go/bin/godep restore ./...
COPY . /go/src/github.com/philpep/kubernetes-image-sync
RUN CGO_ENABLED=0 go build /go/src/github.com/philpep/kubernetes-image-sync

FROM alpine:3.9
RUN apk add --no-cache ca-certificates
COPY --from=builder /go/kubernetes-image-sync /usr/local/bin/
RUN adduser -D -u 1000 user
USER user
ENV USER user
ENTRYPOINT ["/usr/local/bin/kubernetes-image-sync", "--kubeconfig", "/config"]
