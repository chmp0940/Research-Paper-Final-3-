# Base Paper Implementation: Lattice-Based Forward Secure IBE for IoT

## Reference Paper
**"A lattice-based forward secure IBE scheme for Internet of things"**

## Overview
This folder contains the **pure base paper** implementation — **without** the novel trust model enhancements.

It implements:
- **Lattice-based IBE** using Dual Regev encryption
- **Forward security** via binary tree key evolution
- **Epoch-bound encryption/decryption**

## What This Does NOT Include
- ❌ Trust Model (TrustManager, trust scores)
- ❌ Dilithium-3 digital signatures
- ❌ Query authentication / signing
- ❌ False Trust Acceptance Rate (FTAR)

These features are the **novel enhancements** added in the proposed paper.

## Files

| File | Description |
|------|-------------|
| `lattice_infrastructure.py` | Lattice primitives: TrapGen, SamplePre, gadget matrix, binary tree, Setup, KeyGen |
| `forward_security.py` | Encrypt/Decrypt (Dual Regev IBE), key evolution, minimal cover |
| `fs_ibe_params.py` | Parameter sets: PARA.512, PARA.768, PARA.1024 |
| `simulation.py` | Full simulation with 3-parameter + device-count metrics |
| `Base_Paper_fs_IBE.ipynb` | Self-contained Jupyter notebook |

## How to Run

### Python Script
```bash
cd Base-Paper-Implementation
python simulation.py
```

### Jupyter Notebook
```bash
jupyter notebook Base_Paper_fs_IBE.ipynb
```
Run all cells from top to bottom.

## Output
- `Results_Report.csv` — 3-parameter benchmarks
- `Device_Metrics.csv` — Device-count metrics (20-100 devices)
- `all_results.json` — Combined JSON for comparison table
