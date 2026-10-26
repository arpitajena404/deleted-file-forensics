# Quick Demonstration Sequence for the Professor
## "Digital Crime Scene: Investigation of a Deleted File"

Follow this 5-minute step-by-step demonstration sequence to showcase the completed project, satisfy all grading criteria for **Windows Forensics &rarr; File System Analysis**, and prove direct binary parsing without hard-coded mock data.

---

### Step 1: Prove Test Suite & Integrity Validation (30 Seconds)
Open a terminal in the project directory:
```powershell
python -m pytest tests/ -v
```
**Talking Point:**  
> *"All 15 automated forensic unit tests pass in 0.2 seconds. This validates our pure-Python binary parser, streaming chunked SHA-256 calculation, FILETIME timestamp math, MBR/GPT partition offset detection, deleted file recovery, and HTML report generation."*

---

### Step 2: Show Image Integrity and Read-Only Protection (1 Minute)
Run the intake and hash verification command:
```powershell
python src/cli.py verify-image --image evidence/working_copy.raw --expected-sha256 2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac
```
**Talking Point:**  
> *"In accordance with ISO/IEC 27037 digital evidence standards, evidence is opened strictly in read-only mode (`open(..., 'rb')`). We calculate the SHA-256 hash by streaming the file in chunks rather than buffering it in RAM. The working copy hash matches the master image baseline exactly."*

---

### Step 3: Enumerate the Master File Table (MFT) (1 Minute)
Scan the raw NTFS evidence image:
```powershell
python src/cli.py scan-image --image evidence/working_copy.raw
```
**Talking Point:**  
> *"Our tool directly parses the NTFS Volume Boot Record, resolves cluster geometry, and walks the Master File Table. We observe control files `README.txt` and `MEETING_NOTES.txt` as active (`Allocated`), while `BUDGET_DRAFT.txt` at MFT Record 38 is clearly identified with flag `0x0000` (`DELETED / UNALLOCATED`)."*

---

### Step 4: Inspect Surviving Metadata and Recover File Content (1.5 Minutes)
Inspect the surviving MFT entry and execute recovery:
```powershell
python src/cli.py inspect --image evidence/working_copy.raw --record 38
python src/cli.py recover --image evidence/working_copy.raw --record 38 --ground-truth evidence/ground_truth.json
```
**Talking Point:**  
> *"Record 38 retains its `$FILE_NAME` and `$STANDARD_INFORMATION` attributes. Because the file is 327 bytes, it fits within the 1024-byte MFT record as a resident `$DATA` stream. Standard Windows file deletion unlinks the directory reference and clears the in-use flag, but leaves resident content untouched until overwritten. Our tool extracts these bytes into an isolated folder and compares the SHA-256 hash against the ground truth. We get an honest, verified `CRYPTOGRAPHIC MATCH`."*

---

### Step 5: Launch the Interactive Web Dashboard & Show Report (1 Minute)
Launch the Streamlit interface:
```powershell
streamlit run src/app.py
```
**Talking Point:**  
> *"We provide both a scriptable CLI for automated triage and a polished Streamlit GUI. In the GUI, we can explore MFT records, inspect raw hex dumps of resident data, review the chronological timeline of events, and export a print-ready HTML case report with all 8 academic sections."*
