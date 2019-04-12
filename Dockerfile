FROM alpine:3.5
WORKDIR /bin

ADD ./ack-kms-plugin /bin/ack-kms-plugin

CMD ["./ack-kms-plugin"]