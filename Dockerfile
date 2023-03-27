FROM golang:1.20.2-alpine as builder

RUN apk add --no-cache git

ENV GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE=on
RUN go version
COPY . /src
WORKDIR /src
RUN go mod download
# TODO RUN make test
RUN go build -a -installsuffix cgo -o /bin/picante cmd/picante/main.go

FROM alpine:3
RUN export PATH=$PATH:/app
WORKDIR /app
COPY --from=builder /bin/picante /app/picante
ENTRYPOINT ["/app/picante"]