FROM golang:1.12-alpine as builder
RUN apk add --no-cache git
RUN adduser -D -u 1000 -h /home/user user
USER user
WORKDIR /home/user
COPY . .
RUN CGO_ENABLED=0 go build

FROM alpine:3.9
RUN apk add --no-cache ca-certificates
COPY --from=builder /home/user/imago /usr/local/bin/
RUN adduser -D -u 1000 user
USER user
ENV USER user
ENTRYPOINT ["/usr/local/bin/imago", "--kubeconfig", "/config"]
