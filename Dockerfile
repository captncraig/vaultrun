FROM golang:1.10-alpine

WORKDIR /go/src/vaultrun
ADD . .

RUN go install



FROM alpine:3.8

COPY --from=0 /go/bin/vaultrun /usr/bin/vaultrun

ENTRYPOINT ["/usr/bin/vaultrun"]