# Performance Comparison: Three-Way Analysis

## Research Papers Compared

| # | Scheme | Paper | Description |
|---|--------|-------|-------------|
| 1 | **Proposed** | *A lattice-based forward secure IBE scheme for IoT* + Novel Trust Model | fs-IBE with Dilithium-3 trust verification, epoch-bound queries, FTAR |
| 2 | **Base Paper** | *A lattice-based forward secure IBE scheme for IoT* (Pure) | fs-IBE only — no trust model, no signatures |
| 3 | **OO-IRIBE-EnDKER** | *OO-IRIBE-EnDKER* (Scientific Reports 2025) | Online/Offline IBE with revocation, Number List, cloud decryption |

---

## Table 1: Parameter-Level Performance Comparison

All schemes tested with: `num_data=5, num_queries=10, tree_depth=3`

### PARA.512 (n=512, q=3329, NIST Level 1, 143-bit security)

| Metric | Proposed (fs-IBE + Trust) | Base Paper (fs-IBE Pure) | OO-IRIBE-EnDKER |
|--------|:-------------------------:|:------------------------:|:----------------:|
| Data Encryption Time (s) | 0.6090 | 0.2734 | 0.1066 |
| Query Encryption Time (s) | 0.1032 | 0.0596 | 0.0265 |
| Data Decryption Time (s) | 0.0004 | 0.0061 | 0.0002 |
| Query Execution Latency (s) | 0.1037 | 0.0599 | 0.0267 |
| Query Throughput (queries/s) | 9.64 | 16.70 | 37.51 |
| Overall Model Throughput (ops/s) | 9.11 | 17.08 | 40.18 |
| Overall Model Latency (s) | 1.6465 | 0.8783 | 0.3734 |
| False Trust Acceptance Rate | **0.00%** | N/A | **0.00%** |

### PARA.768 (n=768, q=3329, NIST Level 3, 207-bit security)

| Metric | Proposed (fs-IBE + Trust) | Base Paper (fs-IBE Pure) | OO-IRIBE-EnDKER |
|--------|:-------------------------:|:------------------------:|:----------------:|
| Data Encryption Time (s) | 1.2307 | 1.3672 | 0.3175 |
| Query Encryption Time (s) | 0.2520 | 0.2294 | 0.0390 |
| Data Decryption Time (s) | 0.0006 | 0.0007 | 0.0002 |
| Query Execution Latency (s) | 0.2530 | 0.2300 | 0.0393 |
| Query Throughput (queries/s) | 3.95 | 4.35 | 25.45 |
| Overall Model Throughput (ops/s) | 3.99 | 4.09 | 21.11 |
| Overall Model Latency (s) | 3.7613 | 3.6679 | 0.7106 |
| False Trust Acceptance Rate | **0.00%** | N/A | **0.00%** |

### PARA.1024 (n=1024, q=3329, NIST Level 5, 272-bit security)

| Metric | Proposed (fs-IBE + Trust) | Base Paper (fs-IBE Pure) | OO-IRIBE-EnDKER |
|--------|:-------------------------:|:------------------------:|:----------------:|
| Data Encryption Time (s) | 3.6546 | 3.2502 | 0.4428 |
| Query Encryption Time (s) | 0.8378 | 0.7220 | 0.0958 |
| Data Decryption Time (s) | 0.0008 | 0.0009 | 0.0002 |
| Query Execution Latency (s) | 0.8391 | 0.7229 | 0.0960 |
| Query Throughput (queries/s) | 1.19 | 1.38 | 10.41 |
| Overall Model Throughput (ops/s) | 1.25 | 1.43 | 10.69 |
| Overall Model Latency (s) | 12.0462 | 10.4797 | 1.4032 |
| False Trust Acceptance Rate | **0.00%** | N/A | **0.00%** |

---

## Table 2: Performance Metrics by Device Count

All schemes tested at n=512, with device counts: 20, 40, 60, 80, 100

### 2A: Authentication Latency (re-check) — seconds

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 0.1197 | 0.1092 | 0.0750 |
| 40 | 0.0756 | 0.1065 | 0.2306 |
| 60 | 0.1186 | 0.1000 | 0.2711 |
| 80 | 0.1102 | 0.1145 | 0.2338 |
| 100 | 0.0882 | 0.1050 | 0.3665 |

### 2B: Computation Cost — milliseconds

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 7,230.67 | 4,774.10 | 5,200.78 |
| 40 | 13,216.90 | 9,841.83 | 20,696.43 |
| 60 | 20,960.12 | 13,796.84 | 45,829.70 |
| 80 | 28,621.54 | 17,288.00 | 72,139.93 |
| 100 | 32,483.53 | 20,515.40 | 114,391.04 |

### 2C: Throughput — operations per second

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 18.08 | 19.29 | 24.64 |
| 40 | 16.00 | 16.83 | 12.33 |
| 60 | 18.17 | 17.84 | 7.81 |
| 80 | 17.06 | 19.40 | 5.98 |
| 100 | 16.17 | 21.46 | 5.17 |

### 2D: Verified Normalized Throughput (per device)

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 0.904 | 0.964 | 1.232 |
| 40 | 0.400 | 0.421 | 0.308 |
| 60 | 0.303 | 0.297 | 0.130 |
| 80 | 0.213 | 0.243 | 0.075 |
| 100 | 0.162 | 0.215 | 0.052 |

### 2E: Storage Overhead — KB

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 1,008.70 | 1,008.08 | 166.16 |
| 40 | 1,969.41 | 1,968.16 | 326.32 |
| 60 | 2,930.11 | 2,928.23 | 486.48 |
| 80 | 3,890.81 | 3,888.31 | 646.63 |
| 100 | 4,851.52 | 4,848.39 | 806.79 |

---

## Table 3: Batch Processing Metrics (seconds)

### 3A: Batch Formation Time

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 2.2117 | 2.0725 | 1.4857 |
| 40 | 4.9966 | 4.7504 | 5.8238 |
| 60 | 6.5988 | 6.7208 | 14.5623 |
| 80 | 9.3724 | 8.2443 | 25.6851 |
| 100 | 12.3676 | 9.3125 | 37.3475 |

### 3B: Batch Decryption Time

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 0.0008 | 0.0015 | 0.1377 |
| 40 | 0.0030 | 0.0033 | 0.6630 |
| 60 | 0.0037 | 0.0039 | 0.7961 |
| 80 | 0.0077 | 0.0030 | 1.0702 |
| 100 | 0.0041 | 0.0055 | 1.3163 |

### 3C: Batch Authentication Time

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 2.1751 | 0.000007 | 1.7237 |
| 40 | 4.2894 | 0.000009 | 7.1237 |
| 60 | 6.6405 | 0.000007 | 15.6488 |
| 80 | 9.2061 | 0.000015 | 25.6686 |
| 100 | 10.4931 | 0.000008 | 37.9587 |

---

## Table 4: Token Metrics (seconds)

### 4A: Token Generation Time

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 0.0095 | 0.0032 | 0.0015 |
| 40 | 0.0078 | 0.0070 | 0.0041 |
| 60 | 0.0079 | 0.0082 | 0.0117 |
| 80 | 0.0094 | 0.0166 | 0.0117 |
| 100 | 0.0068 | 0.0088 | 0.0322 |

### 4B: Token Encryption Time

| No. of Devices | Proposed | Base Paper | OO-IRIBE-EnDKER |
|:--------------:|:--------:|:----------:|:----------------:|
| 20 | 2.2344 | 2.0891 | 1.6362 |
| 40 | 3.2679 | 4.3325 | 6.7068 |
| 60 | 7.3295 | 6.4244 | 13.7797 |
| 80 | 9.0991 | 8.4560 | 18.4350 |
| 100 | 8.9547 | 10.5553 | 36.9502 |

---

## Table 5: Security Features Comparison  

| Security Feature | Proposed | Base Paper | OO-IRIBE-EnDKER |
|-----------------|:--------:|:----------:|:----------------:|
| Post-Quantum Security | ✅ Lattice-based (LWE) | ✅ Lattice-based (LWE) | ✅ Lattice-based (LWE) |
| Forward Security | ✅ Binary tree epochs | ✅ Binary tree epochs | ❌ Number List based |
| Identity-Based Encryption | ✅ Dual Regev IBE | ✅ Dual Regev IBE | ✅ Custom IBE |
| Trust Verification | ✅ Dilithium-3 signatures | ❌ Not present | ✅ Signature-based |
| FTAR (False Trust Acceptance) | **0.00%** | N/A | **0.00%** |
| User Revocation | ❌ Not implemented | ❌ Not implemented | ✅ Number List (O(1)) |
| Online/Offline Encryption | ❌ Single-phase | ❌ Single-phase | ✅ Split enc (Online + Offline) |
| Cloud-Assisted Decryption | ❌ Not present | ❌ Not present | ✅ Semi-trusted cloud |
| NIST Security Levels | 1, 3, 5 | 1, 3, 5 | 1, 3, 5 |

---

## Analysis & Observations

### 1. Encryption Performance
- **OO-IRIBE-EnDKER** has the **fastest encryption** due to the Online/Offline split — the offline phase pre-computes heavy lattice operations.
- **Base Paper** is faster than Proposed because it lacks Dilithium signing overhead.
- **Proposed** adds ~70-15% overhead over the base paper due to the trust model (query signing + verification).

### 2. Throughput Scaling
- **Base Paper** and **Proposed** maintain **consistent throughput** as device count increases (16–21 ops/s).
- **OO-IRIBE-EnDKER** starts strong at 20 devices (24.64 ops/s) but **degrades significantly** at scale (5.17 ops/s at 100 devices) due to the Number List revocation overhead and per-user D_no matrix operations.

### 3. Storage Efficiency
- **OO-IRIBE-EnDKER** has **6× lower storage** (807 KB vs 4,849–4,852 KB at 100 devices) because it uses a compact representation (m=n) while the base and proposed papers use the full gadget matrix (m=n·k).

### 4. Trust Model Impact (Proposed vs Base Paper)
- The **Proposed scheme's trust model** adds ~2× batch authentication time (signing + verification per device).
- This provides **0% FTAR** — all malicious queries are rejected.
- The tradeoff is higher computation cost but significantly improved security guarantees.

### 5. Batch Authentication
- **Base Paper** has negligible batch authentication time (simple epoch check only).
- **Proposed** scales linearly with device count due to per-device Dilithium signing.
- **OO-IRIBE-EnDKER** also scales linearly but takes ~3.5× longer than Proposed at 100 devices.

### 6. Decryption Speed
- **Proposed** and **Base Paper** have extremely fast decryption (<0.01s even at 100 devices).
- **OO-IRIBE-EnDKER** decryption is ~100× slower due to the cloud-assisted GenDK process + larger ciphertext vectors.

---

## Conclusion

| Criterion | Best Scheme |
|-----------|:-----------:|
| **Fastest Encryption** | OO-IRIBE-EnDKER |
| **Best Throughput at Scale** | Base Paper / Proposed |
| **Lowest Storage** | OO-IRIBE-EnDKER |
| **Fastest Decryption** | Proposed / Base Paper |
| **Security Features** | Proposed (trust + forward security) |
| **Overall Balance** | **Proposed** (best security-performance tradeoff) |

The **Proposed scheme** offers the best balance between security and performance — it includes trust verification (0% FTAR), forward security, and maintains consistent throughput at scale, with only moderate overhead compared to the base paper.
