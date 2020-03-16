FROM golang:1.13
ENV GO111MODULE off
WORKDIR /go/src/github.com/AliyunContainerService/ack-kms-plugin
COPY . .
RUN make build

FROM alpine:3.11
WORKDIR /bin

COPY --from=0 /go/src/github.com/AliyunContainerService/ack-kms-plugin/ack-kms-plugin /bin/ack-kms-plugin

CMD ["/bin/ack-kms-plugin"]
