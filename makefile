.PHONY: install dev test lint format typecheck check build push clean

install:
	python3 -m pip install -e .

dev:
	python3 -m pip install -e ".[dev,async,dns]"
	pre-commit install

test:
	pytest --cov=hwatlib --cov-report=term-missing

lint:
	ruff check .
	ruff format --check .

format:
	ruff check . --fix
	ruff format .

typecheck:
	mypy

check: lint typecheck test

build:
	python3 -m build

push: build
	twine check dist/*
	twine upload dist/*

clean:
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache
