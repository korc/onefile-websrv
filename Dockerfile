FROM golang:alpine AS builder
RUN apk update && apk add --no-cache git

COPY go.mod go.sum $GOPATH/src/onefile-websrv/
WORKDIR $GOPATH/src/onefile-websrv/

RUN go mod download && go mod verify

COPY *.go cmd $GOPATH/src/onefile-websrv/
RUN CGO_ENABLED=0 \
  go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/ ./...

FROM scratch

COPY --from=builder /go/bin/* /go/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /var/www/html

VOLUME [ "/var/www" ]
EXPOSE 80 443
ENTRYPOINT ["/go/bin/onefile-websrv"]
