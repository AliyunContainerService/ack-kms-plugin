FROM golang:1.21
ENV GO111MODULE on
WORKDIR /go/src/github.com/AliyunContainerService/ack-kms-plugin

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build

FROM alpine:3.11
WORKDIR /bin

COPY --from=0 /go/src/github.com/AliyunContainerService/ack-kms-plugin/ack-kms-plugin /bin/ack-kms-plugin

CMD ["/bin/ack-kms-plugin"]
