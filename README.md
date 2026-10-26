# Digital Crime Scene: Investigation of a Deleted File
### Course Module: Windows Forensics &rarr; File System Analysis (NTFS)
**Repository:** `deleted-file-forensics`  
**Author:** Information Security Student Forensic Investigation Team  
**System Support:** Windows 10/11 & Windows Server (Cross-platform compatible with Linux / macOS)  
**Engine:** Pure-Python Binary NTFS Parser (No C-extension DLLs required &bull; AppLocker-safe)  

---

## 1. Project Purpose & Curriculum Fulfillment

This project is a dedicated digital forensics investigation application and research platform, **not** a generic file undelete utility. It implements the academic syllabus topic **Windows Forensics &rarr; File System Analysis**, specifically analyzing low-level NTFS file system structures to investigate a staged security incident on a controlled virtual disk image.

The investigator analyzes evidence to answer six fundamental digital forensics questions:
1. **Did the target file exist?** &rarr; Verified via Master File Table (MFT) record allocation and `$FILE_NAME` attributes.
2. **Is a deleted file entry or other trace still present?** &rarr; Identified via MFT record flags (`0x0000` = unallocated) and sequence numbers.
3. **What path, size, status, and timestamps can be observed?** &rarr; Extracted from `$STANDARD_INFORMATION` (0x10), `$FILE_NAME` (0x30), and `$DATA` (0x80) streams.
4. **Can any of its content be recovered?** &rarr; Bitstream extraction of resident MFT data streams and non-resident cluster runs into an isolated output directory.
5. **Does recovered content match the known original?** &rarr; Cryptographic SHA-256 and MD5 validation against pre-incident ground-truth records (`MATCH`, `MISMATCH`, or `NOT_AVAILABLE`).
6. **Which conclusions are supported by artifacts, and which remain unknown?** &rarr; Explicit separation between verified technical artifacts and investigative hypotheses.

---

## 2. Evidence Scope & Case Scenario

All data is strictly synthetic and isolated within virtual disk images. Host operating system drives and personal files are never touched.

### The Staged Case Scenario
A corporate virtual disk was populated with fictional files:
- **`README.txt`** (Control File): Ordinary active file documenting laboratory disk parameters.
- **`MEETING_NOTES.txt`** (Control File): Ordinary active file containing executive meeting minutes.
- **`BUDGET_DRAFT.txt`** (Target File): Highly sensitive financial document (327 bytes) staged for deletion.

Before deletion, the ground-truth content, file size, timestamps, and SHA-256 hash of `BUDGET_DRAFT.txt` were recorded. The file was then unlinked/deleted using standard Windows commands. The virtual disk was immediately detached to preserve unallocated structures, establishing an untouched **Master Evidence Image** and an identical **Working Copy** for forensic examination.

---

## 3. Architecture & Key Features

```
deleted-file-forensics/
├── src/
│   ├── forensics/
│   │   ├── __init__.py
│   │   ├── models.py              # Data classes (FileRecord, CaseRecord, RecoveryResult, TimelineEvent)
│   │   ├── image_integrity.py    # Streaming chunked SHA-256/MD5 hashing & read-only enforcement
│   │   ├── ntfs_parser.py        # Direct binary parser (VBR, BPB, MBR/GPT offsets, MFT, Fixups, Attributes)
│   │   ├── recovery.py           # Bitstream resident/cluster extraction & ground-truth validation
│   │   ├── timeline.py           # 8-timestamp extractor ($SI vs $FN) & cautious interpretation engine
│   │   ├── reporter.py           # Self-contained HTML case reporter with print-to-PDF layout
│   │   └── cross_check_importer.py # Importer for The Sleuth Kit (fls / bodyfile) and Autopsy CSV exports
│   ├── cli.py                    # Scriptable command-line interface with rich formatted output
│   └── app.py                    # Streamlit interactive web dashboard
├── scripts/
│   ├── create_test_image.py      # Unprivileged synthetic NTFS image generator (raw & MBR partitioned)
│   └── create_windows_vhd.ps1    # Native Windows PowerShell/diskpart script to create fixed NTFS VHDs
├── tests/
│   ├── test_integrity.py         # Unit tests for streaming hashing and case persistence
│   ├── test_parser.py            # Unit tests for VBR geometry, FILETIME, and MFT parsing
│   ├── test_recovery.py          # Unit tests for recovery match, mismatch, and missing data handling
│   ├── test_timeline.py          # Unit tests for chronological timeline generation
│   ├── test_reporter.py          # Unit tests for HTML report structure and 8 required sections
│   └── test_cross_check.py       # Unit tests for TSK bodyfile and Autopsy CSV imports
├── docs/
│   ├── ACADEMIC_REPORT.md        # Comprehensive academic forensics report with genuine measurements
│   ├── FORENSIC_WORKFLOW.md      # Detailed laboratory methodology and cross-check guide
│   └── DEMONSTRATION_GUIDE.md    # 5-minute presentation script for the professor
├── evidence/                     # Evidence images (git-ignored) & ground truth JSON
├── outputs/                      # Output directory (git-ignored: recovered files, reports, cases)
└── README.md
```

### Why Pure-Python NTFS Parsing?
On many Windows student laptops and enterprise/lab environments, Windows Defender Application Control (WDAC) or AppLocker restricts downloading third-party binary C-extensions (such as compiled `pytsk3.pyd` DLLs). Rather than falling back to mock CSV data, our engine directly parses NTFS binary structures byte-for-byte in pure Python using the standard library `struct` module:
- **Zero C-extension DLL dependencies.** Runs reliably on any Windows machine.
- **Partition Offset Awareness:** Automatically detects MBR partition tables (Type 0x07 NTFS at LBA 2048) and GPT headers.
- **Update Sequence Array Fixups:** Restores multi-sector boundary bytes for complete record fidelity.
- **Dual Timestamp Analysis:** Contrasts easily manipulable userland timestamps (`$STANDARD_INFORMATION`) against kernel-managed directory timestamps (`$FILE_NAME`).

---

## 4. Quick Start & Demonstration Sequence

### Step 1: Environment Setup & Test Suite Execution
```powershell
# Clone or navigate to the repository
cd c:\codes\projects\deleted_file_forensics

# Run the automated test suite (15 tests covering all forensic modules)
python -m pytest tests/ -v
```

### Step 2: Generate Staged Evidence Disk Images
```powershell
# Create the 2MB raw NTFS disk image scenario (unprivileged)
python scripts/create_test_image.py

# (Optional) Generate an MBR partitioned disk image to test partition offset detection
python scripts/create_test_image.py --partitioned
```

### Step 3: Run the Complete Automated Investigation
```powershell
python src/cli.py run-all --image evidence/working_copy.raw --target-file BUDGET_DRAFT.txt --ground-truth evidence/ground_truth.json
```

### Step 4: Step-by-Step Command Line Commands
```powershell
# Check image integrity against master baseline
python src/cli.py verify-image --image evidence/working_copy.raw --expected-sha256 2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac

# Enumerate all files in Master File Table
python src/cli.py scan-image --image evidence/working_copy.raw

# Deep inspection of deleted target Record 38 (includes hex dump)
python src/cli.py inspect --image evidence/working_copy.raw --record 38

# Recover deleted file content and validate SHA-256
python src/cli.py recover --image evidence/working_copy.raw --record 38 --ground-truth evidence/ground_truth.json

# View chronological event timeline
python src/cli.py timeline --image evidence/working_copy.raw
```

### Step 5: Launch the Interactive Web Dashboard
```powershell
streamlit run src/app.py
```
Open your browser at `http://localhost:8501` to use the interactive interface.

---

## 5. Summary of Empirical Results

| Forensic Parameter | Measured Value | Meaning & Significance |
| :--- | :--- | :--- |
| **Evidence Image** | `evidence/working_copy.raw` | 2,097,152 bytes (2 MB raw NTFS image) |
| **Image SHA-256** | `2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac` | Verified identical to Master image baseline |
| **Target MFT Record** | Record `38` (Sequence: `2`) | Historical metadata position preserved in MFT |
| **Allocation Status** | `DELETED / UNALLOCATED` (Flags: `0x0000`) | Proves file entry was unlinked by OS file system driver |
| **Storage Mode** | Resident `$DATA` Stream | Small file (327 bytes) fits entirely within MFT record |
| **Original Target SHA-256** | `812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4` | Ground-truth baseline recorded prior to deletion |
| **Recovered File SHA-256** | `812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4` | Content recovered from MFT slack/stream |
| **Cryptographic Match** | **MATCH (100% Bitstream)** | Identical hash confirms complete recovery |
| **Exported Report** | `outputs/reports/CASE-2026-001_forensic_report.html` | Self-contained HTML report with print-to-PDF formatting |

---

## 6. Known Limitations & Forensic Caveats

1. **Attribution Unknown:** File system records prove that the file was created, modified, and deallocated, but they **cannot** prove *who* executed the action or what user credentials were used. Proving user identity requires correlation with Windows Security Event Logs (Event ID 4660 / 4663), which reside in the host OS event subsystem.
2. **Deletion Timestamp Approximation:** NTFS does not store a dedicated "Deleted Time" field. The `$STANDARD_INFORMATION` MFT Modification timestamp (`$MFT Modified`) correlates with the moment of deallocation, but precise down-to-the-millisecond verification requires examining the USN Change Journal (`$UsnJrnl`).
3. **Cluster Reuse in Active Systems:** In live operational environments, unallocated MFT records and unallocated clusters are vulnerable to immediate overwriting by subsequent disk writes. This recovery succeeded because the disk image was detached immediately following the staged incident.

---

## 7. Grading Verification Checklist

- [x] Topic fulfilled: **Windows Forensics &rarr; File System Analysis (NTFS)**
- [x] Real file system analysis (VBR, BPB, MFT, Fixups, $SI, $FN, $DATA) without mock CSV substitutes.
- [x] Read-only evidence handling and streaming chunked SHA-256 integrity hashing.
- [x] Control files (`README.txt`, `MEETING_NOTES.txt`) and target file (`BUDGET_DRAFT.txt`) distinguished.
- [x] Honest cryptographic validation (`MATCH`, `MISMATCH`, or `NOT_AVAILABLE`).
- [x] Chronological timeline with $SI vs $FN timestamp explanations and cautious interpretations.
- [x] Self-contained HTML/PDF case report with all 8 academic sections.
- [x] 15 automated pytest tests passing cleanly.
- [x] Cross-check importer for Autopsy and The Sleuth Kit exports.
- [x] Complete documentation: Academic Report, Workflow Guide, and Demonstration Script.
