FROM golang:1.24-alpine as builder
RUN apk add --no-cache git ca-certificates
RUN adduser -D -u 1000 -h /var/lib/imago imago
USER imago
WORKDIR /var/lib/imago
COPY . .
RUN CGO_ENABLED=0 go build

FROM scratch
COPY --from=builder /var/lib/imago/imago /usr/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /var/empty /var/lib/imago
USER 1000
ENV USER=imago
ENV HOME=/var/lib/imago
WORKDIR /var/lib/imago
ENTRYPOINT ["/usr/bin/imago"]
