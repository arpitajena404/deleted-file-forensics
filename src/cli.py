"""
Command Line Interface (CLI) for Digital Crime Scene Investigation.
Provides robust commands for forensic intake, image verification, MFT scanning,
deleted file search, data recovery, timeline reconstruction, and case reporting.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    HAVE_RICH = True
    console = Console()
except ImportError:
    HAVE_RICH = False
    console = None

from src.forensics.image_integrity import (
    calculate_image_hashes,
    create_case_record,
    load_case_record,
    verify_image_immutability,
)
from src.forensics.ntfs_parser import NTFSParser, detect_partition_offset
from src.forensics.recovery import attempt_recovery, load_ground_truth
from src.forensics.timeline import build_forensic_timeline
from src.forensics.reporter import generate_case_report
from src.forensics.cross_check_importer import parse_bodyfile, parse_autopsy_csv
from src.forensics import __version__


def print_banner():
    msg = f"Digital Crime Scene: Investigation of a Deleted File (v{__version__})\nWindows Forensics -> File System Analysis"
    if HAVE_RICH:
        console.print(Panel(msg, style="bold cyan", border_style="bright_blue"))
    else:
        print("=" * 70)
        print(msg)
        print("=" * 70)


def cmd_init_case(args):
    """Initializes a new case record and establishes image integrity baseline."""
    print_banner()
    abs_img = os.path.abspath(args.image)
    if not os.path.isfile(abs_img):
        print(f"[!] Error: Disk image file not found: {abs_img}")
        sys.exit(1)

    print(f"[*] Hashing evidence image: {abs_img}...")
    sha256_hash, md5_hash, size_bytes = calculate_image_hashes(abs_img)

    offset = args.offset
    if offset is None:
        offset, desc = detect_partition_offset(abs_img)
        print(f"[*] Auto-detected NTFS partition geometry: {desc}")

    case = create_case_record(
        case_id=args.case_id,
        case_name=args.case_name,
        examiner_name=args.examiner,
        image_path=abs_img,
        is_working_copy=not args.is_master,
        master_sha256=args.master_sha256 or (sha256_hash if args.is_master else None),
        partition_offset_bytes=offset,
        examiner_notes=args.notes or "",
    )

    print(f"[+] Case record successfully created: outputs/cases/{case.case_id}.json")
    print(f"    Case ID:     {case.case_id}")
    print(f"    SHA-256:     {case.image_sha256}")
    print(f"    MD5:         {case.image_md5}")
    print(f"    Size:        {case.image_size_bytes:,} bytes")
    print(f"    Type:        {'Master Image' if args.is_master else 'Working Copy'}")
    if case.master_sha256:
        match_str = "MATCH" if case.master_sha256.lower() == case.image_sha256.lower() else "MISMATCH"
        print(f"    Integrity:   {match_str} vs Master Baseline")


def cmd_verify_image(args):
    """Verifies that an evidence image matches its expected baseline hash."""
    print_banner()
    abs_img = os.path.abspath(args.image)
    print(f"[*] Verifying image integrity: {abs_img}...")
    sha256_hash, md5_hash, size_bytes = calculate_image_hashes(abs_img)

    print(f"    Current SHA-256: {sha256_hash}")
    print(f"    Expected SHA-256: {args.expected_sha256}")

    if sha256_hash.lower() == args.expected_sha256.lower():
        print("[+] SUCCESS: Cryptographic integrity verified! Image is unmodified.")
    else:
        print("[!] CAUTION: Hash MISMATCH! Evidence image may have been altered or corrupted.")
        sys.exit(2)


def cmd_scan_image(args):
    """Scans and parses the NTFS Master File Table."""
    print_banner()
    abs_img = os.path.abspath(args.image)
    offset = args.offset
    if offset is None:
        offset, desc = detect_partition_offset(abs_img)
        print(f"[*] Detected partition offset: {offset} bytes ({desc})")

    parser = NTFSParser(abs_img, partition_offset=offset)
    records = parser.scan_all_records()

    print(f"[+] Parsed {len(records)} Master File Table records.")

    if HAVE_RICH:
        table = Table(title="NTFS Master File Table Enumeration")
        table.add_column("Record", style="cyan", justify="right")
        table.add_column("Seq", justify="right")
        table.add_column("Status", style="bold")
        table.add_column("Type")
        table.add_column("Size", justify="right")
        table.add_column("Filename", style="green")
        table.add_column("Path")

        for r_num, r in sorted(records.items()):
            status_style = "green" if r.in_use else "red"
            status_txt = "Allocated" if r.in_use else "DELETED"
            r_type = "Dir" if r.is_directory else "File"
            table.add_row(
                str(r.record_number),
                str(r.sequence_number),
                f"[{status_style}]{status_txt}[/{status_style}]",
                r_type,
                f"{r.file_size:,} B",
                r.filename,
                r.path,
            )
        console.print(table)
    else:
        print(f"{'Record':<8} {'Status':<12} {'Size':<10} {'Filename':<25} {'Path'}")
        print("-" * 75)
        for r_num, r in sorted(records.items()):
            status_txt = "Allocated" if r.in_use else "DELETED"
            print(f"{r.record_number:<8} {status_txt:<12} {r.file_size:<10} {r.filename:<25} {r.path}")


def cmd_search(args):
    """Searches file records by filename, status, or extension."""
    print_banner()
    abs_img = os.path.abspath(args.image)
    offset = args.offset
    if offset is None:
        offset, _ = detect_partition_offset(abs_img)

    parser = NTFSParser(abs_img, partition_offset=offset)
    results = parser.search_files(
        query=args.query or "",
        status_filter=args.status.upper(),
        extension_filter=args.ext or "",
    )

    print(f"[*] Found {len(results)} matching records (Query: '{args.query}', Status: {args.status}):")
    for r in results:
        status_txt = "ALLOCATED" if r.in_use else "DELETED / UNALLOCATED"
        print(f"  [MFT #{r.record_number:2d}] {status_txt:<22} Size: {r.file_size:4d} bytes | {r.filename} ({r.path})")


def cmd_inspect(args):
    """Displays in-depth forensic metadata and hex preview for a specific MFT record."""
    print_banner()
    abs_img = os.path.abspath(args.image)
    offset = args.offset
    if offset is None:
        offset, _ = detect_partition_offset(abs_img)

    parser = NTFSParser(abs_img, partition_offset=offset)
    records = parser.scan_all_records()

    target = None
    if args.record is not None:
        target = records.get(args.record)
    elif args.filename:
        for r in records.values():
            if r.filename.lower() == args.filename.lower():
                target = r
                break

    if not target:
        print(f"[!] File record not found for query: record={args.record}, filename={args.filename}")
        sys.exit(1)

    print(f"=== Metadata Inspection for MFT Record {target.record_number} ===")
    print(f"Filename:          {target.filename}")
    print(f"Full Path:         {target.path}")
    print(f"Allocation Status: {'Active / Allocated' if target.in_use else 'DELETED / UNALLOCATED (Flags: 0x0000)'}")
    print(f"Sequence Number:   {target.sequence_number}")
    print(f"File Size:         {target.file_size} bytes (Allocated: {target.allocated_size} bytes)")
    print(f"Storage:           {'Resident ($DATA fits within MFT record)' if target.is_resident else 'Non-Resident'}")
    print(f"Source Artifact:   {target.source_artifact}")
    print("\n--- Timestamps (UTC) ---")
    print(f"  $SI Created:       {target.si_created or 'unknown'}")
    print(f"  $SI Modified:      {target.si_modified or 'unknown'}")
    print(f"  $SI MFT Modified:  {target.si_mft_modified or 'unknown'}")
    print(f"  $SI Last Accessed: {target.si_accessed or 'unknown'}")
    print(f"  $FN Created:       {target.fn_created or 'unknown'}")
    print(f"  $FN Modified:      {target.fn_modified or 'unknown'}")
    print(f"  $FN MFT Modified:  {target.fn_mft_modified or 'unknown'}")
    print(f"  $FN Last Accessed: {target.fn_accessed or 'unknown'}")

    if target.resident_data:
        print("\n--- Hex Dump of Resident Data (First 256 bytes) ---")
        print(target.hex_preview)


def cmd_recover(args):
    """Attempts recovery of a deleted file and compares SHA-256 against ground truth."""
    print_banner()
    abs_img = os.path.abspath(args.image)
    offset = args.offset
    if offset is None:
        offset, _ = detect_partition_offset(abs_img)

    parser = NTFSParser(abs_img, partition_offset=offset)
    records = parser.scan_all_records()

    target = None
    if args.record is not None:
        target = records.get(args.record)
    elif args.filename:
        for r in records.values():
            if r.filename.lower() == args.filename.lower():
                target = r
                break

    if not target:
        print(f"[!] Deleted target not found in image: {args.filename or args.record}")
        sys.exit(1)

    gt_data = None
    if args.ground_truth:
        gt_full = load_ground_truth(args.ground_truth)
        gt_data = gt_full.get("target_file") if "target_file" in gt_full else gt_full

    res = attempt_recovery(parser, target, case_id=args.case_id, ground_truth_record=gt_data)

    print("\n=== Recovery and Verification Result ===")
    print(f"Target Filename:     {res.target_filename} (MFT #{res.record_number})")
    print(f"Verification Status: {res.status}")
    print(f"Recovered Path:      {res.recovered_path or 'not recoverable in this test'}")
    print(f"Recovered Size:      {res.recovered_size} bytes")
    print(f"Recovered SHA-256:   {res.recovered_sha256 or 'not available'}")
    print(f"Ground Truth SHA-256:{res.ground_truth_sha256 or 'not provided'}")
    print(f"Examiner Notes:      {res.investigative_notes}")


def cmd_timeline(args):
    """Builds and displays chronological timeline of extracted file system timestamps."""
    print_banner()
    abs_img = os.path.abspath(args.image)
    offset = args.offset
    if offset is None:
        offset, _ = detect_partition_offset(abs_img)

    parser = NTFSParser(abs_img, partition_offset=offset)
    records = parser.scan_all_records()
    events = build_forensic_timeline(list(records.values()), include_allocated=not args.deleted_only)

    print(f"[*] Extracted {len(events)} chronological forensic events:")
    if HAVE_RICH:
        table = Table(title="Chronological Forensic Event Timeline")
        table.add_column("Timestamp (UTC)", style="cyan")
        table.add_column("Event Type", style="bold")
        table.add_column("File", style="green")
        table.add_column("Status")
        table.add_column("Source Artifact")
        table.add_column("Cautious Interpretation")

        for ev in events:
            ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "unknown"
            status_style = "green" if ev.allocation_status == "Allocated" else "red"
            table.add_row(
                ts_str,
                ev.timestamp_name,
                ev.filename,
                f"[{status_style}]{ev.allocation_status}[/{status_style}]",
                ev.source_artifact,
                ev.investigator_note or "Normal operation",
            )
        console.print(table)
    else:
        for ev in events:
            ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if ev.timestamp else "unknown"
            print(f"[{ts_str}] {ev.timestamp_name:<38} | {ev.filename:<18} | {ev.allocation_status:<10} | {ev.source_artifact}")


def cmd_report(args):
    """Generates the comprehensive HTML case report."""
    print_banner()
    case = load_case_record(args.case_id)
    parser = NTFSParser(case.image_path, partition_offset=case.partition_offset_bytes)
    records = parser.scan_all_records()

    target_rec = None
    target_name = args.target_file.lower()
    for r in records.values():
        if r.filename.lower() == target_name:
            target_rec = r
            break

    gt_data = None
    if args.ground_truth:
        gt_full = load_ground_truth(args.ground_truth)
        gt_data = gt_full.get("target_file") if "target_file" in gt_full else gt_full

    rec_res = None
    if target_rec:
        rec_res = attempt_recovery(parser, target_rec, case_id=case.case_id, ground_truth_record=gt_data)

    events = build_forensic_timeline(list(records.values()))
    rep_path = generate_case_report(
        case_record=case,
        target_record=target_rec,
        all_records=list(records.values()),
        recovery_result=rec_res,
        timeline_events=events,
    )

    print(f"[+] Forensic Case Report successfully generated: {rep_path}")


def cmd_run_all(args):
    """Runs a complete end-to-end investigation workflow."""
    print_banner()
    abs_img = os.path.abspath(args.image)
    print(f"=== Starting Automated Investigation for Image: {abs_img} ===")

    # 1. Intake and Hashing
    offset = args.offset
    if offset is None:
        offset, desc = detect_partition_offset(abs_img)
        print(f"[*] Partition Offset: {offset} bytes ({desc})")

    sha256_hash, md5_hash, size_bytes = calculate_image_hashes(abs_img)
    case = create_case_record(
        case_id=args.case_id,
        case_name=args.case_name,
        examiner_name=args.examiner,
        image_path=abs_img,
        is_working_copy=True,
        master_sha256=args.master_sha256,
        partition_offset_bytes=offset,
        examiner_notes="Automated forensic investigation pipeline execution.",
    )
    print(f"[1/5] Case Record Initialized: {case.case_id} (Image SHA-256: {case.image_sha256})")

    # 2. Parse MFT
    parser = NTFSParser(abs_img, partition_offset=offset)
    records = parser.scan_all_records()
    print(f"[2/5] MFT Records Parsed: {len(records)} entries found.")

    # 3. Target File Analysis & Recovery
    target_rec = None
    target_name = args.target_file.lower()
    for r in records.values():
        if r.filename.lower() == target_name:
            target_rec = r
            break

    if target_rec:
        print(f"[3/5] Target file '{target_rec.filename}' identified at MFT Record {target_rec.record_number}.")
        print(f"      Allocation Status: {'Allocated' if target_rec.in_use else 'DELETED / UNALLOCATED'}")
    else:
        print(f"[3/5] Target file '{args.target_file}' NOT found in MFT.")

    gt_data = None
    if args.ground_truth:
        gt_full = load_ground_truth(args.ground_truth)
        gt_data = gt_full.get("target_file") if "target_file" in gt_full else gt_full

    rec_res = None
    if target_rec:
        rec_res = attempt_recovery(parser, target_rec, case_id=case.case_id, ground_truth_record=gt_data)
        print(f"      Recovery Outcome: {rec_res.status} (SHA-256: {rec_res.recovered_sha256})")

    # 4. Timeline
    events = build_forensic_timeline(list(records.values()))
    print(f"[4/5] Chronological Timeline Built: {len(events)} events extracted.")

    # 5. Report
    rep_path = generate_case_report(
        case_record=case,
        target_record=target_rec,
        all_records=list(records.values()),
        recovery_result=rec_res,
        timeline_events=events,
    )
    print(f"[5/5] Report Exported: {rep_path}")
    print("\n[+] Full Investigation Completed Successfully!")


def main():
    parser = argparse.ArgumentParser(
        description="Digital Crime Scene: Investigation of a Deleted File (Windows Forensics -> File System Analysis)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Forensic sub-commands")

    # init-case
    p_init = subparsers.add_parser("init-case", help="Initialize case record and hash image")
    p_init.add_argument("--case-id", required=True, help="Unique Case Identifier")
    p_init.add_argument("--case-name", default="Investigation of Deleted File", help="Case Title")
    p_init.add_argument("--examiner", default="Student Forensic Investigator", help="Examiner Name")
    p_init.add_argument("--image", required=True, help="Path to evidence disk image")
    p_init.add_argument("--is-master", action="store_true", help="Mark evidence as untouched master")
    p_init.add_argument("--master-sha256", help="Master image baseline hash")
    p_init.add_argument("--offset", type=int, help="Partition byte offset")
    p_init.add_argument("--notes", help="Investigator acquisition notes")

    # verify-image
    p_ver = subparsers.add_parser("verify-image", help="Verify image cryptographic hash against baseline")
    p_ver.add_argument("--image", required=True, help="Path to evidence disk image")
    p_ver.add_argument("--expected-sha256", required=True, help="Expected SHA-256 hash")

    # scan-image
    p_scan = subparsers.add_parser("scan-image", help="Scan and enumerate NTFS MFT records")
    p_scan.add_argument("--image", required=True, help="Path to disk image")
    p_scan.add_argument("--offset", type=int, help="Partition byte offset")

    # search
    p_search = subparsers.add_parser("search", help="Search file records in image")
    p_search.add_argument("--image", required=True, help="Path to disk image")
    p_search.add_argument("--query", default="", help="Search string")
    p_search.add_argument("--status", choices=["ALL", "ALLOCATED", "DELETED"], default="ALL")
    p_search.add_argument("--ext", default="", help="Filter by file extension")
    p_search.add_argument("--offset", type=int, help="Partition byte offset")

    # inspect
    p_insp = subparsers.add_parser("inspect", help="Inspect MFT metadata and hex dump")
    p_insp.add_argument("--image", required=True, help="Path to disk image")
    p_insp.add_argument("--record", type=int, help="MFT record number")
    p_insp.add_argument("--filename", help="Target filename")
    p_insp.add_argument("--offset", type=int, help="Partition byte offset")

    # recover
    p_rec = subparsers.add_parser("recover", help="Recover deleted file content and verify hash")
    p_rec.add_argument("--image", required=True, help="Path to disk image")
    p_rec.add_argument("--case-id", default="CASE-DEFAULT", help="Case ID for output folder")
    p_rec.add_argument("--record", type=int, help="MFT record number")
    p_rec.add_argument("--filename", default="BUDGET_DRAFT.txt", help="Filename to recover")
    p_rec.add_argument("--ground-truth", help="Path to ground-truth JSON record")
    p_rec.add_argument("--offset", type=int, help="Partition byte offset")

    # timeline
    p_time = subparsers.add_parser("timeline", help="Generate chronological event timeline")
    p_time.add_argument("--image", required=True, help="Path to disk image")
    p_time.add_argument("--deleted-only", action="store_true", help="Include only deleted files")
    p_time.add_argument("--offset", type=int, help="Partition byte offset")

    # report
    p_rep = subparsers.add_parser("report", help="Generate HTML case report")
    p_rep.add_argument("--case-id", required=True, help="Case ID")
    p_rep.add_argument("--target-file", default="BUDGET_DRAFT.txt", help="Target filename")
    p_rep.add_argument("--ground-truth", help="Path to ground-truth JSON record")

    # run-all
    p_all = subparsers.add_parser("run-all", help="Execute complete automated investigation pipeline")
    p_all.add_argument("--case-id", default="CASE-2026-001", help="Case ID")
    p_all.add_argument("--case-name", default="Digital Crime Scene: Investigation of Deleted File", help="Case Name")
    p_all.add_argument("--examiner", default="Student Forensic Investigator", help="Examiner Name")
    p_all.add_argument("--image", default="evidence/working_copy.raw", help="Path to evidence disk image")
    p_all.add_argument("--target-file", default="BUDGET_DRAFT.txt", help="Target filename")
    p_all.add_argument("--ground-truth", default="evidence/ground_truth.json", help="Path to ground truth record")
    p_all.add_argument("--master-sha256", default="2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac", help="Master image baseline hash")
    p_all.add_argument("--offset", type=int, help="Partition byte offset")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "init-case": cmd_init_case,
        "verify-image": cmd_verify_image,
        "scan-image": cmd_scan_image,
        "search": cmd_search,
        "inspect": cmd_inspect,
        "recover": cmd_recover,
        "timeline": cmd_timeline,
        "report": cmd_report,
        "run-all": cmd_run_all,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
