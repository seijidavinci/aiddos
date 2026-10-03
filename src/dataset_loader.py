"""
Dataset Loader and Split Generator for DDoS SDN Framework
Vectorized, high-speed streaming of ready_dataset.csv to generate:
1. baseline_12k.csv (6,000 Benign + 6,000 DDoS across 7 categories)
2. 70/15/15 splits (train: 8,400, val: 1,800, test: 1,800) with random seed 42
3. imbalanced_test.csv
4. unseen_test.csv
5. Full dataset chunked iterators for whole-dataset training
"""
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from typing import Tuple, Dict, Generator, Optional
from src.config import (
    RAW_DATASET_CSV, BASELINE_12K_CSV, TRAIN_CSV, VAL_CSV, TEST_CSV,
    IMBALANCED_TEST_CSV, UNSEEN_TEST_CSV, RANDOM_SEED, ATTACK_CATEGORIES
)
from src.feature_engineering import extract_features_from_df

def build_benchmark_datasets(
    raw_csv_path: str = str(RAW_DATASET_CSV),
    chunk_size: int = 100000
) -> Dict[str, pd.DataFrame]:
    """
    Vectorized extraction from ready_dataset.csv to build:
    - baseline_12k (12,000 records: 6,000 benign + 6,000 DDoS)
    - 70% train (8,400), 15% val (1,800), 15% test (1,800)
    - imbalanced_test.csv
    - unseen_test.csv
    """
    print(f"Streaming from {raw_csv_path} using vectorized chunk filters...")
    
    target_benign = 6000
    target_extra_benign = 2000
    
    cat_targets = {
        "syn_flood": 857,
        "udp_flood": 857,
        "icmp_flood": 857,
        "dns_amplification": 857,
        "http_get_flood": 439,  # All available WebDDoS rows
        "slowloris_low_rate": 1066,
        "pulsed_mixed_flood": 1067
    }
    target_unseen = 1500

    collected_benign = []
    collected_extra_benign = []
    collected_ddos = {cat: [] for cat in cat_targets}
    collected_unseen = []

    benign_count = 0
    extra_benign_count = 0
    ddos_counts = {cat: 0 for cat in cat_targets}
    unseen_count = 0

    chunk_iter = pd.read_csv(raw_csv_path, chunksize=chunk_size, low_memory=False)

    for i, chunk in enumerate(chunk_iter):
        chunk.columns = chunk.columns.str.strip()
        lbl_series = chunk["Label"].astype(str).str.strip().str.upper()

        # 1. Benign
        if benign_count < target_benign:
            b_match = chunk[lbl_series == "BENIGN"]
            if not b_match.empty:
                take = min(len(b_match), target_benign - benign_count)
                collected_benign.append(b_match.iloc[:take])
                benign_count += take
                # remainder for extra benign
                if len(b_match) > take and extra_benign_count < target_extra_benign:
                    rem = min(len(b_match) - take, target_extra_benign - extra_benign_count)
                    collected_extra_benign.append(b_match.iloc[take:take+rem])
                    extra_benign_count += rem
        elif extra_benign_count < target_extra_benign:
            b_match = chunk[lbl_series == "BENIGN"]
            if not b_match.empty:
                take = min(len(b_match), target_extra_benign - extra_benign_count)
                collected_extra_benign.append(b_match.iloc[:take])
                extra_benign_count += take

        # 2. syn_flood
        if ddos_counts["syn_flood"] < cat_targets["syn_flood"]:
            match = chunk[lbl_series.str.contains("SYN")]
            if not match.empty:
                take = min(len(match), cat_targets["syn_flood"] - ddos_counts["syn_flood"])
                collected_ddos["syn_flood"].append(match.iloc[:take])
                ddos_counts["syn_flood"] += take

        # 3. udp_flood
        if ddos_counts["udp_flood"] < cat_targets["udp_flood"]:
            match = chunk[lbl_series.isin(["UDP", "UDPLAG"])]
            if not match.empty:
                take = min(len(match), cat_targets["udp_flood"] - ddos_counts["udp_flood"])
                collected_ddos["udp_flood"].append(match.iloc[:take])
                ddos_counts["udp_flood"] += take

        # 4. dns_amplification
        if ddos_counts["dns_amplification"] < cat_targets["dns_amplification"]:
            match = chunk[lbl_series == "DNS"]
            if not match.empty:
                take = min(len(match), cat_targets["dns_amplification"] - ddos_counts["dns_amplification"])
                collected_ddos["dns_amplification"].append(match.iloc[:take])
                ddos_counts["dns_amplification"] += take

        # 5. http_get_flood (WebDDoS)
        if ddos_counts["http_get_flood"] < cat_targets["http_get_flood"]:
            match = chunk[lbl_series.str.contains("WEB|HTTP")]
            if not match.empty:
                take = min(len(match), cat_targets["http_get_flood"] - ddos_counts["http_get_flood"])
                collected_ddos["http_get_flood"].append(match.iloc[:take])
                ddos_counts["http_get_flood"] += take

        # 6. slowloris_low_rate (LDAP, MSSQL)
        if ddos_counts["slowloris_low_rate"] < cat_targets["slowloris_low_rate"]:
            match = chunk[lbl_series.isin(["LDAP", "MSSQL"])]
            if not match.empty:
                take = min(len(match), cat_targets["slowloris_low_rate"] - ddos_counts["slowloris_low_rate"])
                collected_ddos["slowloris_low_rate"].append(match.iloc[:take])
                ddos_counts["slowloris_low_rate"] += take

        # 7. pulsed_mixed_flood (SSDP, SNMP, NETBIOS)
        if ddos_counts["pulsed_mixed_flood"] < cat_targets["pulsed_mixed_flood"]:
            match = chunk[lbl_series.isin(["SSDP", "SNMP", "NETBIOS"])]
            if not match.empty:
                take = min(len(match), cat_targets["pulsed_mixed_flood"] - ddos_counts["pulsed_mixed_flood"])
                collected_ddos["pulsed_mixed_flood"].append(match.iloc[:take])
                ddos_counts["pulsed_mixed_flood"] += take

        # 8. icmp_flood (PORTMAP, NTP)
        if ddos_counts["icmp_flood"] < cat_targets["icmp_flood"]:
            match = chunk[lbl_series.isin(["PORTMAP", "NTP"])]
            if not match.empty:
                take = min(len(match), cat_targets["icmp_flood"] - ddos_counts["icmp_flood"])
                collected_ddos["icmp_flood"].append(match.iloc[:take])
                ddos_counts["icmp_flood"] += take

        # 9. unseen (TFTP)
        if unseen_count < target_unseen:
            match = chunk[lbl_series == "TFTP"]
            if not match.empty:
                take = min(len(match), target_unseen - unseen_count)
                collected_unseen.append(match.iloc[:take])
                unseen_count += take

        # Progress check
        all_ddos_done = all(ddos_counts[c] >= cat_targets[c] for c in cat_targets)
        if benign_count >= target_benign and all_ddos_done and unseen_count >= target_unseen:
            print(f"Extraction target satisfied at chunk {i} ({i * chunk_size} rows inspected)!")
            break

    # Build Benign DataFrame
    df_benign = pd.concat(collected_benign, ignore_index=True)
    df_benign["category"] = "benign"
    df_benign["is_ddos"] = 0

    # Build DDoS DataFrame
    ddos_dfs = []
    for cat, dfs in collected_ddos.items():
        if dfs:
            c_df = pd.concat(dfs, ignore_index=True)
            c_df["category"] = cat
            c_df["is_ddos"] = 1
            ddos_dfs.append(c_df)
    
    df_ddos = pd.concat(ddos_dfs, ignore_index=True)
    
    # Ensure exact 6,000 DDoS records
    if len(df_ddos) > 6000:
        df_ddos = df_ddos.sample(n=6000, random_state=RANDOM_SEED)

    print(f"Collected {len(df_benign)} Benign and {len(df_ddos)} DDoS flows.")
    print("DDoS category distribution:")
    print(df_ddos["category"].value_counts())

    # Combine into 12,000 baseline
    df_raw_baseline = pd.concat([df_benign, df_ddos], ignore_index=True)
    df_raw_baseline = df_raw_baseline.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    # Extract 14 engineered features
    X_features = extract_features_from_df(df_raw_baseline)
    df_processed = X_features.copy()
    df_processed["category"] = df_raw_baseline["category"]
    df_processed["is_ddos"] = df_raw_baseline["is_ddos"]

    # Save baseline 12k
    df_processed.to_csv(BASELINE_12K_CSV, index=False)
    print(f"Saved baseline to {BASELINE_12K_CSV} with shape {df_processed.shape}")

    # Split 70% Train (8,400), 15% Val (1,800), 15% Test (1,800)
    train_df, temp_df = train_test_split(
        df_processed,
        test_size=3600,
        random_state=RANDOM_SEED,
        stratify=df_processed["is_ddos"]
    )
    val_df, test_df = train_test_split(
        temp_df,
        test_size=1800,
        random_state=RANDOM_SEED,
        stratify=temp_df["is_ddos"]
    )

    train_df.to_csv(TRAIN_CSV, index=False)
    val_df.to_csv(VAL_CSV, index=False)
    test_df.to_csv(TEST_CSV, index=False)
    print(f"Saved splits: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")

    # Build imbalanced_test.csv (1,620 benign + 180 ddos = 1,800 total, 90% benign)
    if collected_extra_benign:
        extra_b = pd.concat(collected_extra_benign, ignore_index=True)
    else:
        extra_b = df_benign.sample(n=1620, replace=True, random_state=RANDOM_SEED)
    
    if len(extra_b) > 1620:
        extra_b = extra_b.iloc[:1620]
    extra_b["category"] = "benign"
    extra_b["is_ddos"] = 0
    extra_b_feat = extract_features_from_df(extra_b)
    extra_b_feat["category"] = "benign"
    extra_b_feat["is_ddos"] = 0

    attack_sample = test_df[test_df["is_ddos"] == 1].sample(n=180, random_state=RANDOM_SEED)
    df_imbalanced = pd.concat([extra_b_feat, attack_sample], ignore_index=True)
    df_imbalanced = df_imbalanced.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    df_imbalanced.to_csv(IMBALANCED_TEST_CSV, index=False)
    print(f"Saved imbalanced test ({len(df_imbalanced)} rows) to {IMBALANCED_TEST_CSV}")

    # Build unseen_test.csv (TFTP attacks)
    if collected_unseen:
        df_unseen_raw = pd.concat(collected_unseen, ignore_index=True).iloc[:1800]
        df_unseen_raw["category"] = "unseen_attack"
        df_unseen_raw["is_ddos"] = 1
        df_unseen = extract_features_from_df(df_unseen_raw)
        df_unseen["category"] = "unseen_attack"
        df_unseen["is_ddos"] = 1
        df_unseen.to_csv(UNSEEN_TEST_CSV, index=False)
        print(f"Saved unseen test ({len(df_unseen)} rows) to {UNSEEN_TEST_CSV}")

    return {
        "baseline": df_processed,
        "train": train_df,
        "val": val_df,
        "test": test_df,
        "imbalanced": df_imbalanced
    }

def load_data_splits() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load pre-generated train, val, and test splits."""
    if not os.path.exists(TRAIN_CSV) or not os.path.exists(TEST_CSV):
        build_benchmark_datasets()
    train_df = pd.read_csv(TRAIN_CSV)
    val_df = pd.read_csv(VAL_CSV)
    test_df = pd.read_csv(TEST_CSV)
    return train_df, val_df, test_df

def get_whole_dataset_iterator(
    batch_size: int = 100000
) -> Generator[Tuple[pd.DataFrame, pd.Series], None, None]:
    """
    Generator streaming the entire ready_dataset.csv (9,209,309 rows)
    extracting 14 live-compatible features and binary is_ddos labels.
    """
    chunk_iter = pd.read_csv(RAW_DATASET_CSV, chunksize=batch_size, low_memory=False)
    for chunk in chunk_iter:
        chunk.columns = chunk.columns.str.strip()
        X_chunk = extract_features_from_df(chunk)
        y_chunk = (chunk["Label"].astype(str).str.strip().str.upper() != "BENIGN").astype(int)
        yield X_chunk, y_chunk
