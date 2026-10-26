# Academic Forensics Case Report
## Digital Crime Scene: Investigation of a Deleted File
**Curriculum Topic:** Windows Forensics &rarr; File System Analysis (NTFS)  
**Course:** Information Security / Digital Forensics Laboratory  
**Investigator:** Student Forensic Examiner  
**Date of Investigation:** October 26, 2026  
**Case Identifier:** `CASE-2026-001`  
**Tool Version:** `deleted-file-forensics v1.0.0` (Python 3.14.3)  

---

## Executive Summary

An investigation was conducted on a controlled forensic disk image (`evidence/working_copy.raw`) formatted with the Microsoft Windows NTFS file system to answer core questions regarding the lifecycle, deletion, and recoverability of a confidential corporate file: `BUDGET_DRAFT.txt`.

Using direct binary parsing of the Volume Boot Record (VBR) and Master File Table ($MFT), the file system artifacts were analyzed without mounting or altering the evidence image. The target file was definitively proven to have existed on the volume. Although unlinked from the active directory structure, its metadata record (MFT Record 38) and its complete resident data stream remained intact. The recovered file was extracted to an isolated directory and subjected to cryptographic validation, yielding an exact SHA-256 hash match against the staged ground-truth baseline.

---

## 1. Investigative Questions and Verified Findings

| Core Research Question | Empirical Finding | Evidentiary Basis |
| :--- | :--- | :--- |
| **1. Did the target file exist?** | **YES** | Master File Table Record 38 contains intact `$FILE_NAME` and `$STANDARD_INFORMATION` attributes naming `BUDGET_DRAFT.txt` under parent directory Record 5 (Root `\`). |
| **2. Is a deleted file trace present?** | **YES** | MFT Record 38 header flags byte is `0x0000`, signifying that the record's in-use bit is cleared (deallocated / deleted). |
| **3. What path, size, status, and timestamps are observed?** | **Path:** `\BUDGET_DRAFT.txt`<br>**Size:** 327 bytes<br>**Status:** Deleted / Unallocated<br>**Timestamps:** Extracted across 8 timestamps ($SI and $FN) | Parsed from `$FILE_NAME` (0x30), `$DATA` (0x80), and `$STANDARD_INFORMATION` (0x10). |
| **4. Can any of its content be recovered?** | **YES (100% Bitstream)** | File content was resident within MFT Record 38 slack/stream (327 bytes) and was extracted cleanly. |
| **5. Does recovered SHA-256 match original?** | **MATCH** | Recovered SHA-256: `812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4`<br>Baseline SHA-256: `812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4` |
| **6. Which conclusions are supported, and which remain unknown?** | Metadata and content recovery are supported.<br>Human identity and user intent remain **UNKNOWN**. | Physical artifacts do not record user session or motive without OS event log correlation. |

---

## 2. Evidence Acquisition and Chain of Custody

The evidence was acquired as a raw disk image (`.raw`) representing an isolated virtual disk formatted with Windows NTFS 3.1. Prior to any forensic examination, the untouched master image was crypotgraphically fingerprinted, and an identical working copy was generated for active analysis.

- **Master Evidence Path:** `evidence/master_image.raw`
- **Master SHA-256:** `2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac`
- **Working Copy Path:** `evidence/working_copy.raw`
- **Working Copy SHA-256:** `2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac`
- **Verification Status:** **100% Cryptographic Match** (Integrity Verified)
- **Image Size:** 2,097,152 bytes (2.00 MB / 4,096 sectors)
- **Sector Size:** 512 bytes
- **Cluster Size:** 4,096 bytes (8 sectors per cluster)
- **MFT Record Size:** 1,024 bytes (Cluster size &times; 2<sup>-10</sup>)
- **Read-Only Protection:** Opened strictly in binary read-only mode (`open(..., 'rb')`). No write operations were performed on the disk image.

---

## 3. Tool Architecture and Environment

To satisfy Windows Forensics requirements on modern Windows environments where Application Control / AppLocker policies may restrict unapproved C-extension DLLs (e.g., standard `pytsk3.pyd`), this investigation implemented a pure-Python, zero-dependency NTFS binary parser (`src/forensics/ntfs_parser.py`):

1. **Volume Boot Record (VBR) Engine:** Parses BIOS Parameter Block (BPB), verifies OEM ID `NTFS    `, resolves cluster geometry, and locates cluster 4 ($MFT).
2. **Partition Offset Detection:** Scans Sector 0 for MBR partition table (detects 0x07 NTFS partitions at LBA 2048) and Sector 1 for GPT headers, enabling analysis of both raw volumes and partitioned disks.
3. **MFT Multi-Sector Fixup Processor:** Restores original bytes across 512-byte sector boundaries using the update sequence array.
4. **Attribute Parser:** Traverses attribute lists, extracting `$STANDARD_INFORMATION` (0x10), `$FILE_NAME` (0x30), and `$DATA` (0x80) resident streams and non-resident cluster runlists.
5. **Cross-Check Verification Module:** Supports importing The Sleuth Kit (`fls` / bodyfile) and Autopsy CSV export formats for independent tool validation.

---

## 4. File System Artifact Enumeration

Scanning the Master File Table yielded 8 active and unallocated records:

| MFT Record | Sequence | Flags | Status | Size (Bytes) | Filename | Path | Storage Mode |
| :---: | :---: | :---: | :---: | :---: | :--- | :--- | :--- |
| `0` | 1 | `0x0001` | Allocated | 0 | `$MFT` | `\$MFT` | System File |
| `1` | 1 | `0x0001` | Allocated | 0 | `$MFTMirr` | `\$MFT\$MFTMirr` | System File |
| `2` | 1 | `0x0001` | Allocated | 0 | `$LogFile` | `\$MFT\$LogFile` | System File |
| `3` | 1 | `0x0001` | Allocated | 0 | `$Volume` | `\$MFT\$Volume` | System File |
| `5` | 1 | `0x0003` | Allocated | 0 | `.` | `\` | Root Directory |
| `36` | 1 | `0x0001` | Allocated | 133 | `README.txt` | `\README.txt` | Resident $DATA |
| `37` | 1 | `0x0001` | Allocated | 138 | `MEETING_NOTES.txt` | `\MEETING_NOTES.txt` | Resident $DATA |
| **`38`** | **2** | **`0x0000`** | **DELETED** | **327** | **`BUDGET_DRAFT.txt`** | **`\BUDGET_DRAFT.txt`** | **Resident $DATA** |

### Detailed Breakdown of Target Record 38

- **Record Header:** Magic `b"FILE"`, offset to first attribute: 56 (`0x38`), record allocated size: 1024 bytes.
- **Flags Byte:** Value is `0x0000`. The lowest bit (In-Use) is `0`. In NTFS architecture, when a file is deleted, Windows clears this flag to mark the MFT record as available for reallocation.
- **Sequence Number:** Value is `2` (incremented from `1` upon deallocation).
- **Parent Directory Index:** 5 (points directly to root directory `\`).
- **Data Stream Attribute (0x80):** Non-resident flag is `0` (Resident). Content length is 327 bytes, located at offset 24 within the attribute.
- **Hex Dump Preview of Resident Data:**
```text
0000  43 4F 4E 46 49 44 45 4E 54 49 41 4C 20 26 20 50   |CONFIDENTIAL & P|
0010  52 49 56 49 4C 45 47 45 44 20 2D 20 41 43 4D 45   |RIVILEGED - ACME|
0020  20 43 4F 52 50 20 32 30 32 36 20 46 49 4E 41 4E   | CORP 2026 FINAN|
0030  43 49 41 4C 20 52 45 53 54 52 55 43 54 55 52 49   |CIAL RESTRUCTURI|
0040  4E 47 20 44 52 41 46 54 0A 44 61 74 65 3A 20 4F   |NG DRAFT.Date: O|
0050  63 74 6F 62 65 72 20 32 34 2C 20 32 30 32 36 0A   |ctober 24, 2026.|
0060  41 75 74 68 6F 72 3A 20 4A 2E 20 44 6F 65 2C 20   |Author: J. Doe, |
0070  44 69 72 65 63 74 6F 72 20 6F 66 20 43 6F 72 70   |Director of Corp|
0080  6F 72 61 74 65 20 46 69 6E 61 6E 63 65 0A 54 61   |orate Finance.Ta|
0090  72 67 65 74 20 41 6C 6C 6F 63 61 74 69 6F 6E 3A   |rget Allocation:|
00A0  20 51 34 20 52 65 64 75 6E 64 61 6E 63 79 20 52   | Q4 Redundancy R|
00B0  65 73 65 72 76 65 3A 20 24 31 2C 34 35 30 2C 30   |eserve: $1,450,0|
00C0  30 30 20 55 53 44 0A 50 72 6F 6A 65 63 74 20 54   |00 USD.Project T|
00D0  69 74 61 6E 20 43 6F 6E 74 69 6E 67 65 6E 63 79   |itan Contingency|
00E0  20 46 75 6E 64 73 3A 20 24 38 32 30 2C 30 30 30   | Funds: $820,000|
00F0  20 55 53 44 0A 4E 6F 74 69 63 65 3A 20 50 72 65   | USD.Notice: Pre|
```

---

## 5. Chronological Event Timeline

Extracting timestamps from both `$STANDARD_INFORMATION` and `$FILE_NAME` yielded 64 timeline events. Below are the key events for the control files and target file:

| Timestamp (UTC) | Event Type | Target File | Status | Source Artifact | Forensic Meaning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **2026-10-24 09:30:00** | File Created | `README.txt` | Allocated | $MFT Record 36 ($SI) | Shell creation timestamp established |
| **2026-10-24 09:45:00** | Content Modified | `README.txt` | Allocated | $MFT Record 36 ($SI) | Last write to README data stream |
| **2026-10-24 10:30:00** | File Created | `MEETING_NOTES.txt` | Allocated | $MFT Record 37 ($SI) | Shell creation timestamp established |
| **2026-10-24 11:15:00** | Content Modified | `MEETING_NOTES.txt` | Allocated | $MFT Record 37 ($SI) | Last write to meeting notes data stream |
| **2026-10-24 11:30:00** | File Created | `BUDGET_DRAFT.txt` | Deleted | $MFT Record 38 ($SI) | Target file initial creation |
| **2026-10-24 11:30:00** | Directory Created | `BUDGET_DRAFT.txt` | Deleted | $MFT Record 38 ($FN) | Directory entry established (timestomp resistant) |
| **2026-10-24 12:00:00** | Content Modified | `BUDGET_DRAFT.txt` | Deleted | $MFT Record 38 ($SI) | Content modification (final financial edits saved) |
| **2026-10-24 12:42:00** | MFT Record Modified | `BUDGET_DRAFT.txt` | Deleted | $MFT Record 38 ($SI) | Kernel updated MFT record (deletion/unlinking event) |

### Timestamp Interpretation and Analysis
- The `$STANDARD_INFORMATION` Modified timestamp (`2026-10-24 12:00:00 UTC`) indicates the final moment the file content was updated.
- The `$STANDARD_INFORMATION` MFT Modified timestamp (`2026-10-24 12:42:00 UTC`) occurred 42 minutes later. This corresponds to the instant the operating system unlinked the file, updated the MFT record flags to `0x0000`, incremented the sequence number to 2, and committed the changes.

---

## 6. Recovery Outcome and Cryptographic Hash Validation

The content of Record 38 was exported to `outputs/recovered/CASE-2026-001/BUDGET_DRAFT.txt`. Cryptographic hashing was performed immediately:

- **Recovered Output Path:** `outputs/recovered/CASE-2026-001/BUDGET_DRAFT.txt`
- **Recovered File Size:** 327 bytes
- **Recovered SHA-256:** `812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4`
- **Ground-Truth SHA-256:** `812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4`
- **Recovered MD5:** `88849b28ec60429788f4cffad9f71ee5`
- **Ground-Truth MD5:** `88849b28ec60429788f4cffad9f71ee5`
- **Validation Outcome:** **CRYPTOGRAPHIC MATCH**

**Forensic Evaluation:**  
Because the file size (327 bytes) was below the resident threshold (~700 bytes), Windows NTFS stored the content directly within the MFT record. Standard unlinking clears the allocation flag but leaves resident data intact until the MFT record index is reassigned to a new file. Recovery was therefore 100% bit-for-bit identical to the original un-deleted document.

---

## 7. Supported Forensic Conclusions

Based strictly on empirical artifacts observed in the disk image:

1. **Existence Proved:** The file `BUDGET_DRAFT.txt` existed on this volume, resided in the root directory (`\`), and occupied MFT Record 38.
2. **Deallocation Proved:** The file was deallocated (deleted) from the active file system, as evidenced by MFT header flags `0x0000`.
3. **Content Integrity Proved:** The recovered file content is 100% authentic and complete, matching the staged ground-truth SHA-256 hash.
4. **Active Control Files Intact:** Control files `README.txt` (Record 36) and `MEETING_NOTES.txt` (Record 37) remained active (`0x0001`), demonstrating that deletion specifically targeted Record 38.

---

## 8. Limitations and Investigative Unknowns

1. **Attribution Unknown:** The file system timestamps and MFT records prove *what* occurred, but they do **not** identify *who* deleted the file or which user account was active. Attribution requires host OS event logs (Security Event Log Event ID 4660 / 4663), which are external to the disk image.
2. **Deletion Tool / Method Caveat:** While the deallocation is evident in the MFT flags, whether the deletion was performed via Windows Explorer (Recycle Bin bypass / Shift+Delete), PowerShell `Remove-Item`, or automated cleanup cannot be determined from the MFT record alone without `$UsnJrnl` (USN Change Journal) parsing.
3. **Real-World Volatility:** In a live Windows operating system with active disk writes, unallocated MFT records are rapidly reused. This recovery was possible because the virtual disk was detached immediately after deletion before overwrite occurred.

---

**Report Authorized By:**  
Student Forensic Examiner  
Lead Investigator, Information Security Laboratory  
*Report Generated: 2026-10-26*
