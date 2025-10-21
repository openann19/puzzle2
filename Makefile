PY := python3
VENV := .venv
GPU_BATCH_SIZE := 256

.PHONY: setup setup-gpu run run-gpu test clean gpu-info

setup:
	@test -d $(VENV) || python3 -m venv $(VENV)
	@. $(VENV)/bin/activate && pip install -U pip && pip install -r requirements.txt

setup-gpu:
	@echo "[*] Installing GPU support (CuPy)..."
	@. $(VENV)/bin/activate && pip install cupy-cuda12x || pip install cupy-cuda11x || echo "[!] GPU setup failed; CPU fallback will be used"

run:
	@. $(VENV)/bin/activate && $(PY) solve_puzzle.py --config solver_config.yaml --mode full

run-gpu:
	@. $(VENV)/bin/activate && $(PY) solve_puzzle_gpu.py --config solver_config.yaml --mode full --gpu-batch-size $(GPU_BATCH_SIZE)

gpu-info:
	@. $(VENV)/bin/activate && $(PY) gpu_decrypt.py

test:
	@. $(VENV)/bin/activate && pytest -q

clean:
	@rm -rf .venv .solver_out
