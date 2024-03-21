.PHONY: piacante
picante:
	go build -o bin/picante cmd/picante/*.go

test: check fmt vet
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
	export KUBECONFIG="${HOME}/.kube/config" && go build -o bin/picante cmd/picante/*.go && go run cmd/picante/main.go

generate-mocks:
	go run github.com/vektra/mockery/v2 --inpackage --case snake --srcpkg ./internal/monitor --name Client
	go run github.com/vektra/mockery/v2 --inpackage --case snake --srcpkg ./internal/attestation --name Verifier

check:
	go version
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go run golang.org/x/tools/cmd/deadcode@latest -filter "internal/test/client.go" -filter "internal/test/test.go" -test ./...

helm-lint:
	helm lint --strict ./charts