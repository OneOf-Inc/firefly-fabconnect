FROM golang:1.17-alpine3.13 AS fabconnect-builder
RUN apk add make git
WORKDIR /fabconnect

COPY ./fabric-sdk-go /fabconnect/fabric-sdk-go
WORKDIR /fabconnect/fabric-sdk-go
RUN git checkout oneof-ext-wallet
WORKDIR /fabconnect

ADD go.mod go.sum ./

RUN go mod download -x
ADD . .
RUN make build

FROM alpine:latest
WORKDIR /fabconnect
COPY --from=fabconnect-builder /fabconnect/fabconnect ./
ADD ./openapi ./openapi/
RUN ln -s /fabconnect/fabconnect /usr/bin/fabconnect
ENTRYPOINT [ "fabconnect" ]
