.PHONY: piacante
picante:
	go build -o bin/picante cmd/picante/*.go

test: fmt vet
	go test ./... -coverprofile cover.out -short
fmt:
	go fmt ./...
vet:
	go vet ./...

coverage.out:
	go test -race -v -count=1 -covermode=atomic -coverprofile=coverage.out ./... || true

cover-html: coverage.out
	go tool cover -html=$<

dtrack:
	docker compose -f local/docker-compse-dtrack.yaml up

local:
	go run cmd/picante/main.go