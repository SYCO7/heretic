.PHONY: install test bench lint docker

install:
	pip install -e ".[dev]"

test:
	pytest -q

bench:
	heretic bench

lint:
	ruff check src tests

docker:
	docker build -t heretic .
