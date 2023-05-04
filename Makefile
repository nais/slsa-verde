.PHONY: piacante
picante:
	go build -o bin/picante cmd/picante/*.go

test: fmt vet
	go test ./... -coverprofile cover.out -short
fmt:
	go run mvdan.cc/gofumpt -w ./
vet:
	go vet ./...

coverage.out:
	go test -race -v -count=1 -covermode=atomic -coverprofile=coverage.out ./... || true

cover-html: coverage.out
	go tool cover -html=$<

dtrack-up:
	docker compose -f hack/docker-compse-dtrack.yaml up

dtrack-down:
	docker compose -f hack/docker-compse-dtrack.yaml down

local:
	go run cmd/picante/main.go