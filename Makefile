.PHONY: install lint test demo clean

PYTHON ?= python3

install:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt && pip install -e ".[dev]"

lint:
	ruff check src tests scripts examples

test:
	pytest

demo:
	python scripts/run_demo.py

clean:
	rm -rf .venv .pytest_cache .ruff_cache results/demo
