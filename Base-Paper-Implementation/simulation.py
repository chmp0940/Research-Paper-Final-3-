"""
╔══════════════════════════════════════════════════════════════════════╗
║  Base Paper: Full Simulation & Benchmarking — fs-IBE (Pure)          ║
║                                                                      ║
║  Paper: "A lattice-based forward secure IBE scheme for IoT"          ║
║                                                                      ║
║  This is the PURE base paper implementation WITHOUT the novel        ║
║  trust model enhancements (no Dilithium signatures, no TrustManager, ║
║  no FTAR). Only lattice-based IBE + forward security via binary tree.║
║                                                                      ║
║  Metrics:                                                            ║
║    - Data encryption time, Query encryption time                     ║
║    - Data decryption time, Query execution latency                   ║
║    - Query throughput, Overall model throughput, Overall model latency║
║    - Device-count-based metrics (20-100 devices)                     ║
╚══════════════════════════════════════════════════════════════════════╝
"""
import sys
import time
import csv
import json
import os

import lattice_infrastructure as P1
from forward_security import UserOps
import fs_ibe_params


# ═══════════════════════════════════════════════════════════════
#  SECTION 1: CORE SIMULATION (3 Parameter Sets)
# ═══════════════════════════════════════════════════════════════

def run_simulation(n=64, num_data=5, num_queries=10, tree_depth=3, param_name=None):
    """
    Run base paper fs-IBE workflow (NO trust model).
    Pipeline:
      1. Setup (TrapGen, binary tree)
      2. Encrypt data (Dual Regev IBE)
      3. Encrypt queries (same fs-IBE encrypt — no signing, no trust)
      4. Match query to data (epoch match)
      5. Decrypt matched data
    """
    params = P1.LatticeParams(n=n)
    system = P1.Setup(tree_depth=tree_depth, params=params)
    ops = UserOps(system)

    user_id = "Alice"
    epoch = 1
    nodes = list(range(min(epoch + 2, 2 ** tree_depth)))
    keys = ops.simulate_key_evolution(user_id, nodes)

    # ---- Data encryption (IoT stream) ----
    t0 = time.perf_counter()
    encrypted_data = []
    for i in range(num_data):
        bit = i % 2
        ct = ops.Encrypt(user_id, epoch, bit)
        encrypted_data.append(ct)
    data_encryption_time = time.perf_counter() - t0

    # ---- Query encryption time (T_Enc^Q) ----
    # Base paper: query = just fs-IBE encrypt of keyword (no signing)
    t_enc_q_list = []
    query_cts = []
    for _ in range(num_queries):
        t0 = time.perf_counter()
        keyword_ct = ops.Encrypt(user_id, epoch, 1)
        t_enc_q_list.append(time.perf_counter() - t0)
        query_cts.append(keyword_ct)
    query_encryption_time = sum(t_enc_q_list) / len(t_enc_q_list) if t_enc_q_list else 0

    # ---- Match (T_Match): epoch-based matching ----
    t_match_list = []
    for qct in query_cts:
        t0 = time.perf_counter()
        matched = [i for i, ct in enumerate(encrypted_data) if ct["epoch"] == qct["epoch"]]
        t_match_list.append(time.perf_counter() - t0)
    match_time = sum(t_match_list) / len(t_match_list) if t_match_list else 0

    # ---- Data decryption time ----
    t0 = time.perf_counter()
    for ct in encrypted_data:
        ops.Decrypt(ct, keys)
    data_decryption_time = time.perf_counter() - t0

    # ---- Decryption time per query (T_Dec) ----
    t_dec_list = []
    for qct in query_cts:
        matched = [i for i, ct in enumerate(encrypted_data) if ct["epoch"] == qct["epoch"]]
        t0 = time.perf_counter()
        for idx in matched:
            ops.Decrypt(encrypted_data[idx], keys)
        t_dec_list.append(time.perf_counter() - t0)
    query_decryption_time = sum(t_dec_list) / len(t_dec_list) if t_dec_list else 0

    # Query execution latency: T_Query = T_Enc^Q + T_Match + T_Dec
    # (no T_Trust in base paper)
    t_query = query_encryption_time + match_time + query_decryption_time

    # ---- Throughput ----
    total_query_time = t_query * num_queries
    query_throughput = num_queries / total_query_time if total_query_time > 0 else 0

    # ---- Overall model ----
    overall_latency = data_encryption_time + total_query_time + data_decryption_time
    total_ops = num_data + num_queries
    overall_throughput = total_ops / overall_latency if overall_latency > 0 else 0

    out = {
        "data_encryption_time_s": data_encryption_time,
        "query_encryption_time_s": query_encryption_time,
        "data_decryption_time_s": data_decryption_time,
        "query_execution_latency_s": t_query,
        "query_throughput_per_s": query_throughput,
        "overall_model_throughput_per_s": overall_throughput,
        "overall_model_latency_s": overall_latency,
        "false_trust_acceptance_rate": "N/A",
        "num_data": num_data,
        "num_queries": num_queries,
        "num_malicious": 0,
        "malicious_accepted": 0,
    }
    if param_name is not None:
        out["parameter"] = param_name
        out["n"] = n
    return out


def print_results(metrics, param_name=None):
    """Print results table."""
    if param_name:
        print("\n" + "=" * 60, flush=True)
        print(f"  Parameter: {param_name}  (n = {metrics.get('n', '—')})", flush=True)
        print("=" * 60, flush=True)
    else:
        print("\n" + "=" * 60, flush=True)
        print("  Results (Base Paper — fs-IBE Pure)", flush=True)
        print("=" * 60, flush=True)
    print(f"  Data encryption time          : {metrics['data_encryption_time_s']:.6f} s", flush=True)
    print(f"  Query encryption time         : {metrics['query_encryption_time_s']:.6f} s", flush=True)
    print(f"  Data decryption time          : {metrics['data_decryption_time_s']:.6f} s", flush=True)
    print(f"  Query execution latency       : {metrics['query_execution_latency_s']:.6f} s  (T_Enc^Q + T_Match + T_Dec)", flush=True)
    print(f"  Query throughput              : {metrics['query_throughput_per_s']:.2f} queries/s", flush=True)
    print(f"  Overall model throughput      : {metrics['overall_model_throughput_per_s']:.2f} ops/s", flush=True)
    print(f"  Overall model latency         : {metrics['overall_model_latency_s']:.6f} s", flush=True)
    print(f"  Trust model                   : N/A (base paper — no trust verification)", flush=True)
    print("=" * 60, flush=True)


def run_all_three_parameters(num_data=5, num_queries=10, tree_depth=3):
    """Run simulation for PARA.512, PARA.768, PARA.1024."""
    all_metrics = []
    for row in fs_ibe_params.FS_IBE_TABLE:
        param_name = row["parameter"]
        n = row["n"]
        print(f"\n  Running simulation for {param_name} (n={n}) ...", flush=True)
        m = run_simulation(n=n, num_data=num_data, num_queries=num_queries,
                           tree_depth=tree_depth, param_name=param_name)
        m["bits_security"] = row["bits_security"]
        m["nist_level"] = row["nist_level"]
        all_metrics.append(m)
    return all_metrics


def print_results_all_three(all_metrics):
    """Print results for each parameter set."""
    for m in all_metrics:
        print_results(m, param_name=m["parameter"])


def save_csv_all_three(all_metrics, path="Results_Report.csv"):
    """Save one row per parameter to CSV."""
    if not all_metrics:
        return
    fieldnames = [
        "parameter", "n", "bits_security", "nist_level",
        "data_encryption_time_s", "query_encryption_time_s",
        "data_decryption_time_s", "query_execution_latency_s",
        "query_throughput_per_s", "overall_model_throughput_per_s",
        "overall_model_latency_s", "false_trust_acceptance_rate",
        "num_data", "num_queries", "num_malicious", "malicious_accepted"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for m in all_metrics:
            w.writerow(m)
    print(f"\n  Saved: {path}  (3 rows: PARA.512, PARA.768, PARA.1024)", flush=True)


# ═══════════════════════════════════════════════════════════════
#  SECTION 2: DEVICE-COUNT METRICS (20, 40, 60, 80, 100 devices)
#  Matching Comparison_Table.docx format
# ═══════════════════════════════════════════════════════════════

def run_device_metrics(device_counts=[20, 40, 60, 80, 100], n=512, tree_depth=3):
    """
    Run device-count-scaled simulations.
    For each device count, simulate that many IoT devices encrypting + querying.

    Returns list of dicts with:
      - No. of devices
      - Auth Latency (re-check) — for base paper: just query latency (no trust auth)
      - Computation Cost — total computation time (setup + enc + dec)
      - Throughput — operations per second
      - Verified_Normalized_Throughput — throughput normalized to device count
      - Storage Overhead — key + ciphertext storage in KB
      - Batch formation time, Batch decryption time, Batch authentication time
      - Token generation time, Token encryption time
    """
    params = P1.LatticeParams(n=n)
    results = []

    for num_devices in device_counts:
        print(f"    Running for {num_devices} devices ...", flush=True)

        # Setup
        t_setup_start = time.perf_counter()
        system = P1.Setup(tree_depth=tree_depth, params=params)
        ops = UserOps(system)
        t_setup = time.perf_counter() - t_setup_start

        user_id = "Device"
        epoch = 1
        nodes = list(range(min(epoch + 2, 2 ** tree_depth)))
        keys = ops.simulate_key_evolution(user_id, nodes)

        # ---- Batch Formation: encrypt data from all devices ----
        t_batch_form_start = time.perf_counter()
        encrypted_data = []
        for i in range(num_devices):
            ct = ops.Encrypt(f"Device_{i}", epoch, i % 2)
            encrypted_data.append(ct)
        batch_formation_time = time.perf_counter() - t_batch_form_start

        # ---- Batch Decryption ----
        # Generate keys for all devices, then decrypt
        t_batch_dec_start = time.perf_counter()
        for ct in encrypted_data:
            ops.Decrypt(ct, keys)
        batch_decryption_time = time.perf_counter() - t_batch_dec_start

        # ---- Batch Authentication ----
        # Base paper has NO trust model, so auth = just re-check epoch validity
        t_batch_auth_start = time.perf_counter()
        for ct in encrypted_data:
            _ = ct["epoch"] == epoch  # simple epoch validation only
        batch_auth_time = time.perf_counter() - t_batch_auth_start

        batch_total = batch_formation_time + batch_decryption_time + batch_auth_time

        # ---- Token Generation & Encryption ----
        t_token_gen_start = time.perf_counter()
        for _ in range(num_devices):
            _ = P1.G_vector(f"token_{epoch}", params)
        token_generation_time = time.perf_counter() - t_token_gen_start

        t_token_enc_start = time.perf_counter()
        for _ in range(num_devices):
            ops.Encrypt(user_id, epoch, 1)
        token_encryption_time = time.perf_counter() - t_token_enc_start

        # ---- Query Latency (re-check) ----
        # Base paper: just encryption latency per query (no trust verification)
        t_query_start = time.perf_counter()
        for _ in range(min(10, num_devices)):
            ops.Encrypt(user_id, epoch, 1)
        query_total = time.perf_counter() - t_query_start
        auth_latency = query_total / min(10, num_devices)

        # ---- Computation Cost ----
        computation_cost = t_setup + batch_formation_time + batch_decryption_time + token_encryption_time

        # ---- Throughput ----
        total_ops = num_devices * 2  # encrypt + decrypt per device
        total_time = batch_formation_time + batch_decryption_time
        throughput = total_ops / total_time if total_time > 0 else 0

        # ---- Normalized Throughput ----
        normalized_throughput = throughput / num_devices if num_devices > 0 else 0

        # ---- Storage Overhead ----
        # Key storage: sk vector (2*m integers) + ciphertext (c1 vector + c2 scalar)
        key_size_bytes = params.m * 2 * 4  # 2*m int32 values
        ct_size_bytes = (params.m * 2 + 1) * 4  # c1 vector + c2 scalar
        storage_overhead_kb = (key_size_bytes + ct_size_bytes * num_devices) / 1024

        results.append({
            "num_devices": num_devices,
            "auth_latency_s": auth_latency,
            "computation_cost_ms": computation_cost * 1000,
            "throughput_ops_s": throughput,
            "normalized_throughput": normalized_throughput,
            "storage_overhead_kb": storage_overhead_kb,
            "batch_formation_s": batch_formation_time,
            "batch_decryption_s": batch_decryption_time,
            "batch_authentication_s": batch_auth_time,
            "token_generation_s": token_generation_time,
            "token_encryption_s": token_encryption_time,
        })

    return results


def save_device_metrics_csv(results, path="Device_Metrics.csv"):
    """Save device-count metrics to CSV."""
    if not results:
        return
    fieldnames = list(results[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            w.writerow(r)
    print(f"  Saved: {path}", flush=True)


def print_device_metrics(results):
    """Print device-count metrics table."""
    print("\n" + "=" * 100, flush=True)
    print("  Device-Count Metrics (Base Paper — fs-IBE Pure)", flush=True)
    print("=" * 100, flush=True)
    header = f"  {'Devices':<10} {'Auth Lat(s)':<14} {'Comp Cost(ms)':<16} {'Throughput':<14} {'Norm Thru':<12} {'Storage(KB)':<14}"
    print(header, flush=True)
    print("  " + "-" * 90, flush=True)
    for r in results:
        print(f"  {r['num_devices']:<10} {r['auth_latency_s']:<14.6f} {r['computation_cost_ms']:<16.2f} "
              f"{r['throughput_ops_s']:<14.2f} {r['normalized_throughput']:<12.2f} {r['storage_overhead_kb']:<14.2f}",
              flush=True)
    print("=" * 100, flush=True)

    print("\n  Batch Processing Metrics:", flush=True)
    header2 = f"  {'Devices':<10} {'Batch Form(s)':<16} {'Batch Dec(s)':<14} {'Batch Auth(s)':<16}"
    print(header2, flush=True)
    print("  " + "-" * 60, flush=True)
    for r in results:
        print(f"  {r['num_devices']:<10} {r['batch_formation_s']:<16.6f} {r['batch_decryption_s']:<14.6f} "
              f"{r['batch_authentication_s']:<16.6f}", flush=True)

    print("\n  Token Metrics:", flush=True)
    header3 = f"  {'Devices':<10} {'Token Gen(s)':<14} {'Token Enc(s)':<14}"
    print(header3, flush=True)
    print("  " + "-" * 40, flush=True)
    for r in results:
        print(f"  {r['num_devices']:<10} {r['token_generation_s']:<14.6f} {r['token_encryption_s']:<14.6f}",
              flush=True)
    print("=" * 100, flush=True)


# ═══════════════════════════════════════════════════════════════
#  SECTION 3: JSON OUTPUT (for comparison table generator)
# ═══════════════════════════════════════════════════════════════

def save_all_results_json(param_metrics, device_metrics, path="all_results.json"):
    """Save all results as JSON for the comparison table generator."""
    output = {
        "scheme": "Base Paper (fs-IBE Pure)",
        "parameter_metrics": param_metrics,
        "device_metrics": device_metrics,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"  Saved: {path}", flush=True)


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 65)
    print("  Base Paper (fs-IBE Pure) — Full Simulation & Benchmarking")
    print("  Paper: 'A lattice-based forward secure IBE scheme for IoT'")
    print("  (NO trust model enhancements)")
    print("=" * 65)

    # ---- Part 1: 3 Parameter Sets ----
    print("\n  Part 1: Running for 3 parameter sets (PARA.512/768/1024)...\n")
    all_metrics = run_all_three_parameters(num_data=5, num_queries=10)
    print_results_all_three(all_metrics)
    save_csv_all_three(all_metrics, path="Results_Report.csv")

    # ---- Part 2: Device-Count Metrics ----
    print("\n  Part 2: Running device-count metrics (20-100 devices)...\n")
    device_results = run_device_metrics(
        device_counts=[20, 40, 60, 80, 100], n=512, tree_depth=3
    )
    print_device_metrics(device_results)
    save_device_metrics_csv(device_results, path="Device_Metrics.csv")

    # ---- Part 3: Combined JSON ----
    save_all_results_json(all_metrics, device_results, path="all_results.json")

    print("\n  Done.")
    print("=" * 65)
