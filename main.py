from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import io
from typing import Optional

app = FastAPI()

# Allow all origins for simplicity, but for production, you should restrict this.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- In-memory data storage ---
LOG_DF = None

# --- Column Aliasing ---
COLUMN_ALIASES = {
    'call_timestamp': ['timestamps', 'call time', 'call_time', 'start_time'],
    'a_party_number': ['a party', 'caller', 'from_number', 'a_party'],
    'b_party_number': ['b_party', 'callee', 'to_number', 'b party'],
    'duration': ['call duration', 'duration_seconds', 'length'],
    'ip_address': ['ip', 'source_ip', 'user_ip', 'ip address']
}

# --- Predefined Suspicious Data ---
MALICIOUS_NUMBERS = {'9999999999', '8888888888'}
SUSPICIOUS_IPS = {"198.51.100.5", "203.0.113.10", "192.0.2.25"}

def standardize_columns(df):
    """Renames DataFrame columns based on the ALIASES mapping."""
    df_renamed = df.copy()
    # Clean column names first for reliable matching (lowercase, no extra spaces)
    df_renamed.columns = df_renamed.columns.str.strip().str.lower()
    
    for standard_name, alias_list in COLUMN_ALIASES.items():
        for alias in alias_list:
            if alias in df_renamed.columns:
                df_renamed.rename(columns={alias: standard_name}, inplace=True)
                break
    return df_renamed

@app.post("/upload-csv/")
async def upload_csv(file: UploadFile = File(...)):
    global LOG_DF
    try:
        content = await file.read()
        
        # --- FIX: Define data types to prevent wrong inference ---
        # Treat any column that might be a party number as a string ('object')
        potential_number_cols = COLUMN_ALIASES['a_party_number'] + COLUMN_ALIASES['b_party_number']
        dtype_map = {col: 'object' for col in potential_number_cols}

        df = pd.read_csv(io.StringIO(content.decode('utf-8')), dtype=dtype_map)
        
        df_standardized = standardize_columns(df)
        
        if 'call_timestamp' in df_standardized.columns:
            df_standardized['call_timestamp'] = pd.to_datetime(df_standardized['call_timestamp'])
        
        LOG_DF = df_standardized
        # For debugging: print the columns to see if they were standardized correctly
        print("Processed columns:", LOG_DF.columns.tolist()) 
        return {"message": f"Successfully uploaded and processed {len(LOG_DF)} records."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process CSV file: {e}")

@app.get("/logs/")
def get_logs(search: Optional[str] = None):
    if LOG_DF is None:
        return {"results": []}
    
    df = LOG_DF
    if search:
        search_cols = [col for col in ['a_party_number', 'b_party_number'] if col in df.columns]
        if not search_cols:
             return {"results": []}
        
        mask = pd.Series([False] * len(df))
        for col in search_cols:
            mask |= df[col].astype(str).str.contains(search, na=False)
        df = df[mask]
        
    return {"results": df.to_dict('records')}

# --- Detection Endpoints (No changes needed below this line) ---

@app.get("/detect/odd-hours")
async def detect_odd_hours(start_hour: int = 1, end_hour: int = 5):
    if LOG_DF is None or 'call_timestamp' not in LOG_DF.columns:
        raise HTTPException(status_code=404, detail="Timestamp data not available.")
    odd_hour_calls = LOG_DF[LOG_DF['call_timestamp'].dt.hour.between(start_hour, end_hour)]
    return {"results": odd_hour_calls.to_dict('records')}

@app.get("/detect/high-volume")
async def detect_high_volume(threshold: int = 25):
    if LOG_DF is None or 'a_party_number' not in LOG_DF.columns:
        raise HTTPException(status_code=404, detail="Caller data not available.")
    
    call_counts = LOG_DF['a_party_number'].value_counts()
    high_volume_numbers = call_counts[call_counts > threshold].index.tolist()
    high_volume_calls = LOG_DF[LOG_DF['a_party_number'].isin(high_volume_numbers)]
    return {"results": high_volume_calls.to_dict('records')}

@app.get("/detect/malicious-calls")
async def detect_malicious_calls():
    if LOG_DF is None:
        raise HTTPException(status_code=404, detail="No data available.")

    a_party_col = 'a_party_number'
    b_party_col = 'b_party_number'
    
    if a_party_col not in LOG_DF.columns or b_party_col not in LOG_DF.columns:
         raise HTTPException(status_code=404, detail="Party number columns not found.")

    malicious_a = LOG_DF[LOG_DF[a_party_col].isin(MALICIOUS_NUMBERS)]
    malicious_b = LOG_DF[LOG_DF[b_party_col].isin(MALICIOUS_NUMBERS)]
    
    combined = pd.concat([malicious_a, malicious_b]).drop_duplicates()
    return {"results": combined.to_dict('records')}

@app.get("/detect/suspicious-ips")
async def detect_suspicious_ips():
    if LOG_DF is None or 'ip_address' not in LOG_DF.columns:
        raise HTTPException(status_code=404, detail="IP address data not found.")
    
    suspicious_calls = LOG_DF[LOG_DF['ip_address'].isin(SUSPICIOUS_IPS)]
    return {"results": suspicious_calls.to_dict('records')}

@app.get("/detect/same-pattern")
async def detect_same_pattern(time_window_seconds: int = 120, duration_tolerance: int = 10):
    if LOG_DF is None or 'call_timestamp' not in LOG_DF.columns:
        raise HTTPException(status_code=404, detail="Timestamp data not available.")
    
    df_sorted = LOG_DF.sort_values(by='call_timestamp')
    duplicates = df_sorted[df_sorted.duplicated(subset=['a_party_number', 'b_party_number'], keep=False)]
    pattern_calls = []
    
    for _, group in duplicates.groupby(['a_party_number', 'b_party_number']):
        if len(group) > 1:
            time_diffs = group['call_timestamp'].diff().dt.total_seconds().fillna(float('inf'))
            duration_diffs = group['duration'].diff().abs().fillna(float('inf'))
            pattern_mask = (time_diffs <= time_window_seconds) & (duration_diffs <= duration_tolerance)
            
            if pattern_mask.any():
                indices = group.index[pattern_mask | pattern_mask.shift(-1).fillna(False)]
                pattern_calls.extend(indices.tolist())

    unique_indices = list(set(pattern_calls))
    return {"results": LOG_DF.loc[unique_indices].to_dict('records')}