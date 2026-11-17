.PHONY: install test demo lint

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest -q

lint:
	python -m ruff check src tests

demo: install
	python -m skill_security scan tests/fixtures/good_pack --skip-allowlist --no-report
