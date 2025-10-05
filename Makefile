.PHONY: build
build:
	@echo "Building..."
	go build -o ./bin/jakkiserver "./cmd/jakki/main.go"

.PHONY: bin
bin:
	@./bin/jakkiserver

.PHONY: run
run:
	@go run ./cmd/jakki/main.go

.PHONY: tidy
tidy:
	@go mod tidy -v

.PHONY: lint
lint:
	@golangci-lint run

.PHONY: docker-up
docker-up:
	@docker compose up --build -d

.PHONY: docker-down
docker-down:
	@docker compose down
