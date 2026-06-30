.PHONY: up down logs build seed iris-docs

up:
	cp -n .env.example .env || true
	docker compose up -d --build

build:
	docker compose build

logs:
	docker compose logs -f

down:
	docker compose down

reset:
	docker compose down -v

seed:
	./scripts/seed_demo.sh

iris-docs:
	cat infra/dfir-iris/README.md
