"""
cleaner.py — Data cleaning and normalization
Accepts raw records from any of our 3 collectors (all use same schema) and 
produces a unified pandas DataFrame.
"""
import pandas as pd

STANDARD_COLS = ['id', 'ioc', 'ioc_type', 'threat_type', 'malware_alias',
                 'tags', 'confidence_level', 'timestamp', 'source']

def clean_records(records: list) -> pd.DataFrame:
    """Normalize a list of IOC records into a standard DataFrame."""
    if not records:
        return pd.DataFrame(columns=STANDARD_COLS)
    df = pd.DataFrame(records)
    # Ensure all standard columns exist
    for col in STANDARD_COLS:
        if col not in df.columns:
            df[col] = "Unknown"
    df = df[STANDARD_COLS].copy()
    df.fillna("Unknown", inplace=True)
    df['tags'] = df['tags'].astype(str)
    return df

def merge_all_sources(*source_lists) -> pd.DataFrame:
    """Merge records from multiple collectors into one DataFrame."""
    all_records = []
    for lst in source_lists:
        all_records.extend(lst)
    return clean_records(all_records)

# Legacy aliases kept for backward compatibility with main.py
def clean_urlhaus_data(data: list) -> pd.DataFrame:
    return clean_records(data)

def clean_threatfox_data(data: list) -> pd.DataFrame:
    return clean_records(data)

def merge_and_process_threats(list1: list, list2: list) -> pd.DataFrame:
    return merge_all_sources(list1, list2)
