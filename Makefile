PY := python3
VENV := .venv

.PHONY: setup run test clean

setup:
	@test -d $(VENV) || python3 -m venv $(VENV)
	@. $(VENV)/bin/activate && pip install -U pip && pip install -r requirements.txt

run:
	@. $(VENV)/bin/activate && $(PY) solve_puzzle.py --config solver_config.yaml --mode full

test:
	@. $(VENV)/bin/activate && pytest -q

clean:
	@rm -rf .venv .solver_out
