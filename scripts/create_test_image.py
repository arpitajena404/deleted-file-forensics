"""
Synthetic NTFS Evidence Image Generator.
Constructs a valid, byte-compliant raw NTFS disk image and staged case scenario
without requiring administrator privileges or third-party drivers.
Creates:
- Ordinary control files: README.txt, MEETING_NOTES.txt (Allocated)
- Staged deleted target file: BUDGET_DRAFT.txt (Unallocated/Deleted with intact resident data)
- Ground-truth cryptographic baseline (ground_truth.json)
- Master image and separate working copy.
"""

import argparse
import datetime
import hashlib
import json
import os
import struct
from pathlib import Path

# Helper for Windows FILETIME
FILETIME_EPOCH_DIFF = 11644473600

def dt_to_filetime(dt: datetime.datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int((dt.timestamp() + FILETIME_EPOCH_DIFF) * 10000000)


def build_attribute(attr_type: int, attr_id: int, content: bytes, name: str = "") -> bytes:
    """Builds a resident NTFS attribute record."""
    name_bytes = name.encode("utf-16le") if name else b""
    name_len = len(name)
    name_offset = 24 if name else 0
    val_offset = 24 + ((len(name_bytes) + 7) & ~7)
    total_len = val_offset + len(content)
    # Align to 8 bytes
    total_len = (total_len + 7) & ~7

    header = bytearray(val_offset)
    struct.pack_into("<I", header, 0, attr_type)
    struct.pack_into("<I", header, 4, total_len)
    header[8] = 0  # Resident
    header[9] = name_len
    struct.pack_into("<H", header, 10, name_offset)
    struct.pack_into("<H", header, 12, 0)  # Flags
    struct.pack_into("<H", header, 14, attr_id)
    struct.pack_into("<I", header, 16, len(content))  # Value length
    struct.pack_into("<H", header, 20, val_offset)    # Value offset
    header[22] = 0  # Indexed flag
    header[23] = 0  # Padding

    if name_bytes:
        header[name_offset : name_offset + len(name_bytes)] = name_bytes

    return bytes(header) + content + (b"\x00" * (total_len - val_offset - len(content)))


def build_mft_record(
    record_number: int,
    sequence_number: int,
    in_use: bool,
    is_directory: bool,
    filename: str,
    parent_record: int,
    content: bytes,
    c_time: datetime.datetime,
    m_time: datetime.datetime,
    mft_time: datetime.datetime,
    a_time: datetime.datetime,
) -> bytes:
    """Constructs a 1024-byte NTFS MFT record with fixup array and resident attributes."""
    record = bytearray(1024)

    # Magic and Fixup metadata
    record[0:4] = b"FILE"
    fixup_offset = 0x30  # 48
    fixup_count = 3      # 1 sequence + 2 sector fixups
    struct.pack_into("<H", record, 4, fixup_offset)
    struct.pack_into("<H", record, 6, fixup_count)
    struct.pack_into("<Q", record, 8, 0)  # LSN
    struct.pack_into("<H", record, 16, sequence_number)
    struct.pack_into("<H", record, 18, 1)  # Link count
    
    first_attr_offset = 0x38  # 56
    struct.pack_into("<H", record, 20, first_attr_offset)
    
    flags = 0
    if in_use:
        flags |= 0x0001
    if is_directory:
        flags |= 0x0002
    struct.pack_into("<H", record, 22, flags)
    struct.pack_into("<I", record, 28, 1024)  # Allocated size
    struct.pack_into("<Q", record, 32, 0)     # Base record
    struct.pack_into("<H", record, 40, 4)     # Next attribute ID
    struct.pack_into("<I", record, 44, record_number)

    # Update sequence array initial values
    seq_marker = b"\xAA\x55"
    record[fixup_offset : fixup_offset + 2] = seq_marker
    # Sector 1 and 2 placeholders in fixup array
    record[fixup_offset + 2 : fixup_offset + 4] = b"\x11\x22"
    record[fixup_offset + 4 : fixup_offset + 6] = b"\x33\x44"

    # 1. $STANDARD_INFORMATION (0x10)
    si_val = bytearray(72)
    struct.pack_into("<Q", si_val, 0, dt_to_filetime(c_time))
    struct.pack_into("<Q", si_val, 8, dt_to_filetime(m_time))
    struct.pack_into("<Q", si_val, 16, dt_to_filetime(mft_time))
    struct.pack_into("<Q", si_val, 24, dt_to_filetime(a_time))
    struct.pack_into("<I", si_val, 32, 0x20 if not is_directory else 0x10)  # Archive or Directory
    attr_si = build_attribute(0x10, 1, bytes(si_val))

    # 2. $FILE_NAME (0x30)
    name_utf16 = filename.encode("utf-16le")
    fn_val = bytearray(66 + len(name_utf16))
    parent_ref = parent_record | (1 << 48)  # Parent record + sequence
    struct.pack_into("<Q", fn_val, 0, parent_ref)
    struct.pack_into("<Q", fn_val, 8, dt_to_filetime(c_time))
    struct.pack_into("<Q", fn_val, 16, dt_to_filetime(m_time))
    struct.pack_into("<Q", fn_val, 24, dt_to_filetime(mft_time))
    struct.pack_into("<Q", fn_val, 32, dt_to_filetime(a_time))
    struct.pack_into("<Q", fn_val, 40, len(content))  # Allocated size
    struct.pack_into("<Q", fn_val, 48, len(content))  # Real size
    struct.pack_into("<I", fn_val, 56, 0x20 if not is_directory else 0x10)
    fn_val[64] = len(filename)  # Character count
    fn_val[65] = 3              # Win32 & DOS namespace
    fn_val[66 : 66 + len(name_utf16)] = name_utf16
    attr_fn = build_attribute(0x30, 2, bytes(fn_val))

    # 3. $DATA (0x80) (if not directory)
    attr_data = b""
    if not is_directory and content is not None:
        attr_data = build_attribute(0x80, 3, content)

    # Assemble attributes into record
    attrs = attr_si + attr_fn + attr_data + b"\xFF\xFF\xFF\xFF"  # End marker
    used_size = first_attr_offset + len(attrs)
    struct.pack_into("<I", record, 24, used_size)  # Used size

    record[first_attr_offset : first_attr_offset + len(attrs)] = attrs

    # Apply fixup array to sector boundaries (offset 510 and 1022)
    # Sector 1 (ends at byte 512): store original bytes into fixup array, replace with seq_marker
    record[fixup_offset + 2 : fixup_offset + 4] = record[510:512]
    record[510:512] = seq_marker
    # Sector 2 (ends at byte 1024): store original bytes into fixup array, replace with seq_marker
    record[fixup_offset + 4 : fixup_offset + 6] = record[1022:1024]
    record[1022:1024] = seq_marker

    return bytes(record)


def generate_synthetic_case(
    output_dir: str = "evidence",
    include_mbr_partition: bool = False,
) -> dict:
    """
    Creates a full NTFS virtual disk evidence scenario.
    Returns case metadata including hashes and ground truth.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Disk Geometry: 2MB image, 512 bytes/sector, 8 sectors/cluster = 4096 bytes/cluster
    bytes_per_sector = 512
    sectors_per_cluster = 8
    cluster_size = bytes_per_sector * sectors_per_cluster  # 4096
    total_sectors = 4096  # 2MB total
    total_image_size = total_sectors * bytes_per_sector

    # Partition offset: 0 if raw volume, 2048 sectors (1MB) if MBR partitioned
    part_offset_sectors = 2048 if include_mbr_partition else 0
    part_offset_bytes = part_offset_sectors * bytes_per_sector
    full_image_size = total_image_size + part_offset_bytes

    image_buffer = bytearray(full_image_size)

    # If MBR partition requested, write MBR partition table at sector 0
    if include_mbr_partition:
        # Sector 0 MBR signature
        image_buffer[510:512] = b"\x55\xAA"
        # Partition 1 entry at offset 446 (0x1BE)
        p_entry = 446
        image_buffer[p_entry + 0] = 0x80  # Active / Bootable
        image_buffer[p_entry + 4] = 0x07  # NTFS
        struct.pack_into("<I", image_buffer, p_entry + 8, part_offset_sectors)
        struct.pack_into("<I", image_buffer, p_entry + 12, total_sectors)

    # Write NTFS VBR at partition offset
    vbr_offset = part_offset_bytes
    vbr = bytearray(512)
    vbr[0:3] = b"\xEB\x52\x90"
    vbr[3:11] = b"NTFS    "
    struct.pack_into("<H", vbr, 11, bytes_per_sector)
    vbr[13] = sectors_per_cluster
    vbr[21] = 0xF8  # Media descriptor (fixed disk)
    struct.pack_into("<H", vbr, 24, 63)   # Sectors per track
    struct.pack_into("<H", vbr, 26, 255)  # Heads
    struct.pack_into("<Q", vbr, 40, total_sectors)
    
    mft_cluster = 4
    mftmirr_cluster = 2
    struct.pack_into("<Q", vbr, 48, mft_cluster)
    struct.pack_into("<Q", vbr, 56, mftmirr_cluster)
    struct.pack_into("<b", vbr, 64, -10)  # 2^10 = 1024 bytes per MFT record
    vbr[68] = 1                           # Clusters per index buffer
    struct.pack_into("<Q", vbr, 72, 0x1A2B3C4D5E6F7081)  # Volume Serial
    vbr[510:512] = b"\x55\xAA"

    image_buffer[vbr_offset : vbr_offset + 512] = vbr

    # Staged timestamps (realistic timeline)
    base_time = datetime.datetime(2026, 10, 24, 9, 30, 0, tzinfo=datetime.timezone.utc)
    t_readme_c = base_time
    t_readme_m = base_time + datetime.timedelta(minutes=15)
    
    t_notes_c = base_time + datetime.timedelta(hours=1)
    t_notes_m = base_time + datetime.timedelta(hours=1, minutes=45)

    # Target file: BUDGET_DRAFT.txt
    t_budget_c = base_time + datetime.timedelta(hours=2)
    t_budget_m = base_time + datetime.timedelta(hours=2, minutes=30)
    t_budget_mft_del = base_time + datetime.timedelta(hours=3, minutes=12)  # Staged deletion moment!

    # Target Content: Fictional sensitive corporate financial draft
    budget_content = (
        "CONFIDENTIAL & PRIVILEGED - ACME CORP 2026 FINANCIAL RESTRUCTURING DRAFT\n"
        "Date: October 24, 2026\n"
        "Author: J. Doe, Director of Corporate Finance\n"
        "Target Allocation: Q4 Redundancy Reserve: $1,450,000 USD\n"
        "Project Titan Contingency Funds: $820,000 USD\n"
        "Notice: Preliminary draft scheduled for permanent purge prior to regulatory audit."
    ).encode("utf-8")

    budget_sha256 = hashlib.sha256(budget_content).hexdigest().lower()
    budget_md5 = hashlib.md5(budget_content).hexdigest().lower()

    # Control files content
    readme_content = (
        "Digital Forensics Laboratory - Scenario Disk Volume\n"
        "Filesystem: Windows NTFS 3.1\n"
        "Purpose: Academic file system artifact verification."
    ).encode("utf-8")

    notes_content = (
        "Project Titan Strategy Meeting - 24 Oct 2026\n"
        "Attendees: J. Doe, A. Smith, R. Vance\n"
        "Topics: Reviewed budget drafts; approved final figures."
    ).encode("utf-8")

    # Build MFT Records
    mft_records = {}

    # System Records 0..5
    mft_records[0] = build_mft_record(0, 1, True, False, "$MFT", 0, b"", base_time, base_time, base_time, base_time)
    mft_records[1] = build_mft_record(1, 1, True, False, "$MFTMirr", 0, b"", base_time, base_time, base_time, base_time)
    mft_records[2] = build_mft_record(2, 1, True, False, "$LogFile", 0, b"", base_time, base_time, base_time, base_time)
    mft_records[3] = build_mft_record(3, 1, True, False, "$Volume", 0, b"", base_time, base_time, base_time, base_time)
    mft_records[5] = build_mft_record(5, 1, True, True, ".", 5, b"", base_time, base_time, base_time, base_time)

    # User Record 36: README.txt (Allocated)
    mft_records[36] = build_mft_record(
        36, 1, True, False, "README.txt", 5, readme_content,
        t_readme_c, t_readme_m, t_readme_m, t_readme_m
    )

    # User Record 37: MEETING_NOTES.txt (Allocated)
    mft_records[37] = build_mft_record(
        37, 1, True, False, "MEETING_NOTES.txt", 5, notes_content,
        t_notes_c, t_notes_m, t_notes_m, t_notes_m
    )

    # User Record 38: BUDGET_DRAFT.txt (DELETED / UNALLOCATED with in_use = False!)
    # Notice: in_use is False (0x0000), sequence number incremented to 2, MFT modified time reflects deletion
    mft_records[38] = build_mft_record(
        38, 2, False, False, "BUDGET_DRAFT.txt", 5, budget_content,
        t_budget_c, t_budget_m, t_budget_mft_del, t_budget_m
    )

    # Write MFT records into image at cluster 4 (offset: part_offset_bytes + 4 * 4096 = 16384)
    mft_start_offset = part_offset_bytes + (mft_cluster * cluster_size)
    for rec_num, rec_bytes in mft_records.items():
        rec_pos = mft_start_offset + (rec_num * 1024)
        image_buffer[rec_pos : rec_pos + 1024] = rec_bytes

    # Save Ground Truth Record
    ground_truth = {
        "case_name": "Investigation of Deleted File: BUDGET_DRAFT.txt",
        "scenario": "Controlled student virtual Windows NTFS disk image",
        "target_file": {
            "filename": "BUDGET_DRAFT.txt",
            "mft_record": 38,
            "original_size_bytes": len(budget_content),
            "sha256": budget_sha256,
            "md5": budget_md5,
            "created_time_utc": t_budget_c.isoformat(),
            "modified_time_utc": t_budget_m.isoformat(),
            "deletion_event_utc": t_budget_mft_del.isoformat(),
            "content_snippet": budget_content.decode("utf-8")[:100] + "...",
        },
        "control_files": [
            {
                "filename": "README.txt",
                "mft_record": 36,
                "status": "Allocated",
                "size_bytes": len(readme_content),
                "sha256": hashlib.sha256(readme_content).hexdigest().lower(),
            },
            {
                "filename": "MEETING_NOTES.txt",
                "mft_record": 37,
                "status": "Allocated",
                "size_bytes": len(notes_content),
                "sha256": hashlib.sha256(notes_content).hexdigest().lower(),
            },
        ],
        "image_specifications": {
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "total_sectors": total_sectors,
            "partition_offset_bytes": part_offset_bytes,
            "is_mbr_partitioned": include_mbr_partition,
        },
    }

    gt_file = out_path / "ground_truth.json"
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    # Save Master Evidence Image
    master_img_path = out_path / ("partitioned_ntfs.raw" if include_mbr_partition else "master_image.raw")
    with open(master_img_path, "wb") as f:
        f.write(image_buffer)

    # Save Working Copy (identical clone preserved for active examination)
    working_img_path = out_path / ("partitioned_working_copy.raw" if include_mbr_partition else "working_copy.raw")
    with open(working_img_path, "wb") as f:
        f.write(image_buffer)

    master_sha256 = hashlib.sha256(image_buffer).hexdigest().lower()
    working_sha256 = hashlib.sha256(image_buffer).hexdigest().lower()

    return {
        "master_image": str(master_img_path),
        "working_copy": str(working_img_path),
        "ground_truth": str(gt_file),
        "image_size": len(image_buffer),
        "sha256": master_sha256,
        "partition_offset": part_offset_bytes,
        "target_sha256": budget_sha256,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic NTFS forensic test scenario.")
    parser.add_argument("--output-dir", default="evidence", help="Output evidence directory")
    parser.add_argument("--partitioned", action="store_true", help="Generate MBR partitioned disk image")
    args = parser.parse_args()

    meta = generate_synthetic_case(args.output_dir, args.partitioned)
    print("Synthetic Evidence Disk Image generated successfully:")
    print(f"  Master Image:      {meta['master_image']}")
    print(f"  Working Copy:      {meta['working_copy']}")
    print(f"  Image SHA-256:     {meta['sha256']}")
    print(f"  Ground Truth File: {meta['ground_truth']}")
    print(f"  Target File Hash:  {meta['target_sha256']}")
