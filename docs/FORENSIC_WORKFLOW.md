# Forensic Workflow & Technical Guide
## Windows Forensics &rarr; File System Analysis (NTFS)

This document provides complete instructions for setting up the forensic environment, preparing evidence disk images (both unprivileged synthetic raw images and native Windows VHDs), executing the forensic engine, cross-checking findings with Autopsy or The Sleuth Kit, and exporting reports.

---

## 1. Environment & Setup

### Prerequisites
- **Operating System:** Windows 10/11 or Windows Server (also compatible with Linux / macOS for raw image analysis)
- **Python:** Python 3.10+ (tested on Python 3.14.3)
- **Dependencies:** Pure-Python dependencies (`rich`, `streamlit`, `pandas`, `pytest`). No C-extension DLLs required, avoiding Windows AppLocker / Application Control blocks.

### Installation
```powershell
# Navigate to project repository
cd c:\codes\projects\deleted_file_forensics

# Verify Python version
python --version

# Run test suite to verify all 15 unit and integration tests pass
python -m pytest tests/ -v
```

---

## 2. Generating Forensic Evidence Images

You can generate evidence in two ways:

### Method A: Unprivileged Synthetic Raw Disk Image (Recommended & Immediate)
Does **not** require Administrator privileges or disk drivers. Generates a byte-perfect NTFS image with valid VBR, BPB, MFT, control files, and deleted target:

```powershell
# Generate 2MB raw volume (master_image.raw & working_copy.raw)
python scripts/create_test_image.py

# Optionally generate an MBR partitioned disk (partitioned_ntfs.raw with NTFS at LBA 2048)
python scripts/create_test_image.py --partitioned
```

**Generated Assets:**
- `evidence/master_image.raw`: Untouched master evidence image
- `evidence/working_copy.raw`: Analysis clone for examiner examination
- `evidence/ground_truth.json`: Cryptographic baseline record of target and control files

### Method B: Native Windows VHD Creation via PowerShell / Diskpart
Requires **Administrator** privileges. Creates a real 30MB NTFS Virtual Hard Disk using native Windows components:

```powershell
# In an elevated Administrator PowerShell prompt:
powershell -ExecutionPolicy Bypass -File .\scripts\create_windows_vhd.ps1
```

This script:
1. Creates `evidence\disk_scenario.vhd` (30MB fixed disk).
2. Attaches the VHD, formats it with Windows NTFS, and assigns a drive letter.
3. Stages `README.txt`, `MEETING_NOTES.txt`, and `BUDGET_DRAFT.txt`.
4. Computes and records baseline SHA-256 for `BUDGET_DRAFT.txt`.
5. Deletes `BUDGET_DRAFT.txt` via PowerShell `Remove-Item`.
6. Detaches the VHD and generates `evidence\disk_scenario_working.vhd`.

---

## 3. Running the Forensic Application

### Option 1: Automated End-to-End Investigation (CLI)
Run the entire 5-step investigative workflow in a single command:

```powershell
python src/cli.py run-all --image evidence/working_copy.raw --target-file BUDGET_DRAFT.txt --ground-truth evidence/ground_truth.json
```

**Execution Pipeline:**
1. **Intake & Hashing:** Streams image in 1MB chunks; computes SHA-256 and MD5.
2. **MFT Enumeration:** Parses VBR, locates cluster 4, scans MFT records.
3. **Target Analysis & Recovery:** Identifies Record 38, recovers resident bytes, compares SHA-256.
4. **Timeline Generation:** Reconstructs 64 chronological file system events.
5. **Report Export:** Generates HTML audit report at `outputs/reports/CASE-2026-001_forensic_report.html`.

### Option 2: Step-by-Step Command Line Examination

```powershell
# Step 1: Initialize Case Record & Hash Image
python src/cli.py init-case --case-id CASE-2026-001 --image evidence/working_copy.raw --master-sha256 2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac

# Step 2: Verify Working Copy Immutability
python src/cli.py verify-image --image evidence/working_copy.raw --expected-sha256 2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac

# Step 3: Scan MFT and View Table
python src/cli.py scan-image --image evidence/working_copy.raw

# Step 4: Search for Deleted Files
python src/cli.py search --image evidence/working_copy.raw --status DELETED

# Step 5: Deep Metadata & Hex Inspection of Record 38
python src/cli.py inspect --image evidence/working_copy.raw --record 38

# Step 6: Recover Deleted Target and Validate SHA-256
python src/cli.py recover --image evidence/working_copy.raw --record 38 --ground-truth evidence/ground_truth.json

# Step 7: View Forensic Event Timeline
python src/cli.py timeline --image evidence/working_copy.raw

# Step 8: Generate Audit Report
python src/cli.py report --case-id CASE-2026-001 --ground-truth evidence/ground_truth.json
```

### Option 3: Interactive Streamlit Web GUI
Launch the rich graphical user interface:

```powershell
streamlit run src/app.py
```
Open your browser at `http://localhost:8501`. Navigate through the 6 interactive forensic tabs:
- **Tab 1: Case & Image Integrity** (Streaming hash calculation, master verification)
- **Tab 2: File System Browser** (Searchable MFT record directory)
- **Tab 3: Deleted Files Inspector** (Header flags, attributes, interactive hex viewer)
- **Tab 4: Recovery & Hash Verification** (One-click recovery, SHA-256 match badge, file download)
- **Tab 5: Chronological Timeline** (Interactive event correlation)
- **Tab 6: Case Report & Audit** (Live report preview and HTML/PDF download)

---

## 4. Cross-Checking with Autopsy and The Sleuth Kit

To validate findings against independent forensic tools:

### Using The Sleuth Kit (TSK)
If The Sleuth Kit command-line tools are installed:
```bash
# 1. List files including deleted ones
fls -r -p evidence/working_copy.raw

# 2. Inspect MFT Record 38
istat -o 0 evidence/working_copy.raw 38

# 3. Recover file content using icat
icat -o 0 evidence/working_copy.raw 38 > recovered_tsk.txt

# 4. Generate Bodyfile for timeline
fls -m / -r evidence/working_copy.raw > bodyfile.txt
mactime -b bodyfile.txt > timeline_tsk.txt
```

### Cross-Check Importer in Python
If analyzing an export from Autopsy or Sleuth Kit:
```powershell
python -c "
from src.forensics.cross_check_importer import parse_bodyfile, parse_autopsy_csv
body_records = parse_bodyfile('evidence/cross_check_bodyfile.txt')
print(f'Imported {len(body_records)} records from TSK bodyfile.')
target = [r for r in body_records if 'BUDGET_DRAFT.txt' in r['filename']][0]
print(f'Cross-Check Target: {target[\"filename\"]} (MFT #{target[\"record_number\"]}) - Status: {\"Allocated\" if target[\"in_use\"] else \"Deleted\"}')
"
```

---

## 5. Output Artifacts Directory Structure

The application isolates all generated data into the git-ignored `outputs/` folder:
- `outputs/cases/<case_id>.json`: Case metadata, examiners notes, and image SHA-256 hashes.
- `outputs/recovered/<case_id>/`: Recovered file bytes extracted from unallocated MFT records.
- `outputs/reports/<case_id>_forensic_report.html`: Self-contained HTML investigation report with print-to-PDF formatting.
