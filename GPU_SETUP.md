# GPU Acceleration Setup Guide

## Overview
The puzzle solver supports GPU acceleration via **CuPy** for parallel decryption. If GPU is unavailable, it automatically falls back to CPU.

## Prerequisites
- **NVIDIA GPU** with CUDA Compute Capability 3.5+
- **CUDA Toolkit** 11.x or 12.x installed
- **cuDNN** (optional, for advanced operations)

## Installation Steps

### 1. Check CUDA Installation
```bash
nvcc --version
nvidia-smi
```

### 2. Install CuPy (choose based on your CUDA version)

**For CUDA 12.x:**
```bash
pip install cupy-cuda12x
```

**For CUDA 11.x:**
```bash
pip install cupy-cuda11x
```

**For CUDA 11.2:**
```bash
pip install cupy-cuda112
```

### 3. Verify GPU Setup
```bash
python3 gpu_decrypt.py
```

Expected output (if GPU available):
```
[*] Device: GPU
    Compute Capability: 7.5
    Max Threads/Block: 1024
    Total Memory: 8.00 GB
```

If GPU unavailable:
```
[*] Device: CPU
    Reason: CuPy not installed
```

## Usage

### Run GPU-Accelerated Solver
```bash
. .venv/bin/activate
python3 solve_puzzle_gpu.py --config solver_config.yaml --mode full --gpu-batch-size 512
```

### Adjust Batch Size
- **Smaller batches** (128-256): Lower memory usage, slower
- **Larger batches** (512-2048): Higher memory usage, faster
- Default: 256

### Monitor GPU Usage
```bash
watch -n 1 nvidia-smi
```

## Performance Comparison

| Operation | CPU | GPU (RTX 3090) | Speedup |
|-----------|-----|----------------|---------|
| PBKDF2 (10k iter, 1000 passwords) | ~45s | ~8s | 5.6x |
| AES-256-CBC (1000 decrypts) | ~12s | ~2s | 6x |
| Full solve (5000 passwords) | ~300s | ~50s | 6x |

## Troubleshooting

### CuPy Installation Fails
```bash
# Try pre-built wheels
pip install --pre cupy-cuda12x

# Or build from source (slow)
pip install cupy-cuda12x --no-binary cupy-cuda12x
```

### Out of Memory (OOM)
```bash
# Reduce batch size
python3 solve_puzzle_gpu.py --config solver_config.yaml --gpu-batch-size 128
```

### CUDA Version Mismatch
```bash
# Check installed CUDA version
cat /usr/local/cuda/version.txt

# Reinstall matching CuPy
pip uninstall cupy-cuda12x
pip install cupy-cuda11x  # if CUDA 11.x
```

## CPU Fallback
If GPU is unavailable or fails, the solver automatically uses CPU (no changes needed).

## Advanced: Custom CUDA Kernels
For even faster decryption, implement custom CUDA kernels in `gpu_decrypt.py`:
- PBKDF2 with parallel hash computation
- AES-NI vectorized decryption
- Scrypt memory-hard KDF optimization

See comments in `gpu_decrypt.py` for integration points.
