FROM golang:1.23.0 as builder
ENV GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE=on
RUN go version
COPY . /src
WORKDIR /src
RUN go mod download
RUN go build -a -installsuffix cgo -o /bin/slsa-verde cmd/slsa-verde/main.go

FROM cgr.dev/chainguard/go
WORKDIR /app
COPY --from=builder /bin/slsa-verde /app/slsa-verde
ENTRYPOINT ["/app/slsa-verde"]