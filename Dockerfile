FROM golang:alpine AS builder
RUN apk update && apk add --no-cache git

COPY . $GOPATH/src/onefile-websrv/
WORKDIR $GOPATH/src/onefile-websrv/

RUN go get -d -v
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/onefile-websrv
RUN mkdir -p /var/www/html

FROM scratch

COPY --from=builder /go/bin/onefile-websrv /go/bin/onefile-websrv
COPY --from=builder /var/www/html /var/www/html

WORKDIR /var/www/html

VOLUME [ "/var/www" ]
EXPOSE 80 443
ENTRYPOINT ["/go/bin/onefile-websrv"]
