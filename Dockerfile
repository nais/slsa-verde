FROM cgr.dev/chainguard/go:latest as builder
ENV GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE=on
RUN go version
COPY . /src
WORKDIR /src
RUN go mod download
RUN go build -a -installsuffix cgo -o /bin/slsa-verde cmd/slsa-verde/main.go

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /bin/slsa-verde /slsa-verde
ENTRYPOINT ["/slsa-verde"]