"""
Cross-Check Verification Module: Autopsy and The Sleuth Kit Export Importer.
Allows importing external forensic exports (Autopsy CSV/TSV file reports, Sleuth Kit bodyfiles, fls output)
to cross-validate direct NTFS parsing against independent tool outputs.
"""

import csv
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from .models import FileRecord, TimelineEvent


def parse_bodyfile(bodyfile_path: str) -> List[Dict[str, Any]]:
    """
    Parses a standard The Sleuth Kit (TSK) bodyfile format (v3):
    MD5|path/name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    """
    path = Path(bodyfile_path)
    if not path.is_file():
        raise FileNotFoundError(f"Bodyfile not found: {bodyfile_path}")

    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 11:
                continue

            md5, full_name, inode, mode, uid, gid, size_str, atime, mtime, ctime, crtime = parts[:11]
            is_deleted = "(deleted)" in full_name.lower() or full_name.startswith("* ")
            clean_name = re.sub(r"\(deleted\)", "", full_name).lstrip("* ").strip()

            def safe_ts(val_str: str) -> Optional[datetime]:
                try:
                    sec = int(val_str)
                    if sec > 0:
                        return datetime.fromtimestamp(sec, tz=timezone.utc)
                except ValueError:
                    pass
                return None

            records.append({
                "source": "TSK Bodyfile (Cross-Check)",
                "record_number": inode,
                "filename": Path(clean_name).name or clean_name,
                "path": clean_name,
                "in_use": not is_deleted,
                "file_size": int(size_str) if size_str.isdigit() else 0,
                "md5": md5 if md5 != "0" else "",
                "created": safe_ts(crtime),
                "modified": safe_ts(mtime),
                "mft_modified": safe_ts(ctime),
                "accessed": safe_ts(atime),
            })

    return records


def parse_autopsy_csv(csv_path: str) -> List[Dict[str, Any]]:
    """
    Parses an Autopsy File List CSV export.
    Maps columns like 'File Name', 'Metadata Address', 'Size', 'Known', 'Flags', 'Created Time', etc.
    """
    path = Path(csv_path)
    if not path.is_file():
        raise FileNotFoundError(f"Autopsy CSV export not found: {csv_path}")

    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalize column names (lowercase and strip spaces)
            norm = {k.strip().lower(): v for k, v in row.items() if k}
            
            filename = norm.get("file name", norm.get("name", norm.get("filename", "")))
            if not filename:
                continue

            alloc_status = norm.get("flags", norm.get("allocation", norm.get("status", ""))).lower()
            is_deleted = "deleted" in alloc_status or "unalloc" in alloc_status

            meta_addr = norm.get("metadata address", norm.get("meta addr", norm.get("inode", "0")))
            size_str = norm.get("size", norm.get("file size", "0")).replace(",", "")
            
            records.append({
                "source": "Autopsy Export (Cross-Check)",
                "record_number": meta_addr,
                "filename": filename,
                "path": norm.get("path", norm.get("full path", f"\\{filename}")),
                "in_use": not is_deleted,
                "file_size": int(size_str) if size_str.isdigit() else 0,
                "md5": norm.get("md5 hash", norm.get("md5", "")),
                "sha256": norm.get("sha256 hash", norm.get("sha-256", norm.get("sha256", ""))),
                "created_str": norm.get("created time", norm.get("created", "")),
                "modified_str": norm.get("modified time", norm.get("modified", "")),
            })

    return records
