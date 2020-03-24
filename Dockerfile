FROM golang:1.13-alpine as builder
RUN apk add --no-cache git
RUN adduser -D -u 1000 -h /var/lib/imago imago
USER imago
WORKDIR /var/lib/imago
COPY . .
RUN CGO_ENABLED=0 go build

FROM alpine:3.11
RUN apk add --no-cache ca-certificates
COPY --from=builder /var/lib/imago/imago /usr/bin/
RUN adduser -D -u 1000 -h /var/lib/imago imago
USER imago
ENV USER imago
WORKDIR /var/lib/imago
ENTRYPOINT ["/usr/bin/imago"]
