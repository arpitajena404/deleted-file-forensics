"""
Streamlit Web Interface for Digital Crime Scene: Investigation of a Deleted File.
Provides an interactive GUI for forensic disk image analysis, MFT exploration,
deleted file recovery, hash validation, timeline visualization, and case report export.
"""

import os
import sys
from pathlib import Path
import streamlit as st
import pandas as pd

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.forensics.image_integrity import (
    calculate_image_hashes,
    create_case_record,
    load_case_record,
    verify_image_immutability,
)
from src.forensics.ntfs_parser import NTFSParser, detect_partition_offset
from src.forensics.recovery import attempt_recovery, load_ground_truth
from src.forensics.timeline import build_forensic_timeline, format_timeline_table
from src.forensics.reporter import generate_case_report
from src.forensics.cross_check_importer import parse_bodyfile, parse_autopsy_csv
from src.forensics import __version__

# Page configuration
st.set_page_config(
    page_title="Digital Crime Scene: Investigation of a Deleted File",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for forensic badges and tables
st.markdown("""
<style>
    .badge-del {
        background-color: #fee2e2;
        color: #991b1b;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85em;
    }
    .badge-alloc {
        background-color: #dcfce7;
        color: #166534;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85em;
    }
    .badge-match {
        background-color: #15803d;
        color: white;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
    }
    .hex-display {
        font-family: Consolas, "Courier New", monospace;
        background-color: #0f172a;
        color: #38bdf8;
        padding: 12px;
        border-radius: 6px;
        font-size: 13px;
        white-space: pre-wrap;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    if "case_record" not in st.session_state:
        st.session_state.case_record = None
    if "parser" not in st.session_state:
        st.session_state.parser = None
    if "records" not in st.session_state:
        st.session_state.records = {}
    if "recovery_result" not in st.session_state:
        st.session_state.recovery_result = None
    if "timeline_events" not in st.session_state:
        st.session_state.timeline_events = []


init_session_state()

# Sidebar: Case Info & Navigation
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/detective.png", width=64)
    st.title("Digital Crime Scene")
    st.caption(f"Windows Forensics -> File System Analysis (v{__version__})")
    st.divider()

    st.subheader("Active Evidence")
    if st.session_state.case_record:
        cr = st.session_state.case_record
        st.success(f"**Case:** {cr.case_id}")
        st.text(f"Image: {os.path.basename(cr.image_path)}")
        st.text(f"Size: {cr.image_size_bytes:,} B")
        st.code(f"SHA-256:\n{cr.image_sha256[:16]}...", language="text")
        if cr.master_sha256:
            if cr.master_sha256.lower() == cr.image_sha256.lower():
                st.caption("✅ Matches Master Baseline")
            else:
                st.error("⚠️ Hash Mismatch with Master!")
    else:
        st.info("No active case loaded. Begin in Tab 1.")

    st.divider()
    st.markdown("""
    **Investigative Questions:**
    1. Did `BUDGET_DRAFT.txt` exist?
    2. What trace remains in $MFT?
    3. Can data stream be recovered?
    4. Does recovered hash match ground truth?
    """)


# Main Tabs
tabs = st.tabs([
    "1. Case & Image Integrity",
    "2. File System Browser",
    "3. Deleted Files Inspector",
    "4. Recovery & Hash Verification",
    "5. Chronological Timeline",
    "6. Case Report & Audit",
])

# -------------------------------------------------------------
# TAB 1: Case & Image Integrity
# -------------------------------------------------------------
with tabs[0]:
    st.header("1. Case Intake & Image Cryptographic Integrity")
    st.markdown("""
    Forensic integrity demands calculating cryptographic hashes directly via streaming chunks
    from the local filesystem, without modifying evidence.
    """)

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("Case Metadata")
        case_id = st.text_input("Case ID", value="CASE-2026-001")
        case_name = st.text_input("Case Title", value="Investigation of Deleted File: BUDGET_DRAFT.txt")
        examiner = st.text_input("Examiner Name", value="Senior Forensic Examiner")
        examiner_notes = st.text_area("Investigator Intake Notes", value="Controlled laboratory student disk image analysis.")

    with col2:
        st.subheader("Evidence Image File")
        default_img = "evidence/working_copy.raw" if os.path.exists("evidence/working_copy.raw") else ""
        image_path = st.text_input("Disk Image Path (Local Raw/DD/VHD)", value=default_img)
        is_working = st.checkbox("This is a Working Copy (Recommended)", value=True)
        master_hash_input = st.text_input(
            "Master Image SHA-256 Baseline (Optional for verification)",
            value="2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac"
        )
        
        offset_mode = st.radio("Partition Offset", ["Auto-detect partition offset", "Manual byte offset"], horizontal=True)
        manual_offset = 0
        if offset_mode == "Manual byte offset":
            manual_offset = st.number_input("Byte Offset", value=0, step=512)

    if st.button("Initialize Case & Hash Evidence", type="primary"):
        if not os.path.isfile(image_path):
            st.error(f"Image file not found: {image_path}")
        else:
            with st.spinner("Streaming evidence image and computing cryptographic hashes..."):
                abs_path = os.path.abspath(image_path)
                sha256_h, md5_h, size_b = calculate_image_hashes(abs_path)
                
                offset_bytes = manual_offset
                if offset_mode == "Auto-detect partition offset":
                    offset_bytes, desc = detect_partition_offset(abs_path)
                    st.info(f"Geometry detection: {desc}")

                case_rec = create_case_record(
                    case_id=case_id,
                    case_name=case_name,
                    examiner_name=examiner,
                    image_path=abs_path,
                    is_working_copy=is_working,
                    master_sha256=master_hash_input if master_hash_input else None,
                    partition_offset_bytes=offset_bytes,
                    examiner_notes=examiner_notes,
                )
                st.session_state.case_record = case_rec

                # Parse records immediately
                try:
                    parser = NTFSParser(abs_path, partition_offset=offset_bytes)
                    records = parser.scan_all_records()
                    st.session_state.parser = parser
                    st.session_state.records = records
                    st.session_state.timeline_events = build_forensic_timeline(list(records.values()))
                    st.success(f"Evidence loaded successfully! Discovered {len(records)} MFT records.")
                except Exception as e:
                    st.error(f"Failed to parse NTFS filesystem: {e}")

    if st.session_state.case_record:
        st.divider()
        st.subheader("Active Case Record Summary")
        c = st.session_state.case_record
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("File Size", f"{c.image_size_bytes:,} B")
        m2.metric("Partition Offset", f"{c.partition_offset_bytes} B")
        m3.metric("Type", "Working Copy" if c.is_working_copy else "Master")
        if c.master_sha256:
            is_match = c.master_sha256.lower() == c.image_sha256.lower()
            m4.metric("Master Integrity", "MATCH" if is_match else "MISMATCH")
        else:
            m4.metric("Master Integrity", "Self-Baseline")

        st.text_area("SHA-256 Hash", c.image_sha256, disabled=True)
        st.text_area("MD5 Hash", c.image_md5, disabled=True)

# -------------------------------------------------------------
# TAB 2: File System Browser
# -------------------------------------------------------------
with tabs[1]:
    st.header("2. File System Structure & MFT Records")
    if not st.session_state.records:
        st.warning("Please initialize and load an evidence image in Tab 1 first.")
    else:
        records_list = list(st.session_state.records.values())
        alloc_cnt = sum(1 for r in records_list if r.in_use)
        del_cnt = sum(1 for r in records_list if not r.in_use)

        colA, colB, colC = st.columns(3)
        colA.metric("Total MFT Records", len(records_list))
        colB.metric("Active (Allocated)", alloc_cnt)
        colC.metric("Deleted / Unallocated", del_cnt)

        # Filters
        f1, f2, f3 = st.columns([2, 1, 1])
        with f1:
            search_query = st.text_input("Search (Filename, Path, Record #)", "")
        with f2:
            status_filter = st.selectbox("Allocation Filter", ["ALL", "ALLOCATED", "DELETED"])
        with f3:
            ext_filter = st.text_input("Extension (e.g. txt)", "")

        filtered = st.session_state.parser.search_files(
            query=search_query,
            status_filter=status_filter,
            extension_filter=ext_filter,
        )

        # Build display table
        table_data = []
        for r in filtered:
            table_data.append({
                "MFT Record": r.record_number,
                "Sequence": r.sequence_number,
                "Status": "Allocated" if r.in_use else "DELETED",
                "Type": "Directory" if r.is_directory else "File",
                "Size (Bytes)": r.file_size,
                "Resident": "Yes" if r.is_resident else "No",
                "Filename": r.filename,
                "Path": r.path,
                "Modified (UTC)": r.si_modified.strftime("%Y-%m-%d %H:%M:%S") if r.si_modified else "unknown",
            })

        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

# -------------------------------------------------------------
# TAB 3: Deleted Files Inspector
# -------------------------------------------------------------
with tabs[2]:
    st.header("3. Deleted Files & Surviving Artifacts")
    if not st.session_state.records:
        st.warning("Please load an evidence image in Tab 1 first.")
    else:
        deleted_records = [r for r in st.session_state.records.values() if not r.in_use]
        if not deleted_records:
            st.info("No deleted or unallocated records detected in this image.")
        else:
            st.markdown(f"Discovered **{len(deleted_records)}** deleted/unallocated record(s) with surviving metadata:")
            
            del_names = [f"Record {r.record_number}: {r.filename}" for r in deleted_records]
            selected_choice = st.selectbox("Select Deleted Record to Inspect", del_names)
            selected_rec_num = int(selected_choice.split(":")[0].replace("Record", "").strip())
            rec = st.session_state.records[selected_rec_num]

            col_meta1, col_meta2 = st.columns([1, 1])
            with col_meta1:
                st.subheader("Header & Status Metadata")
                st.markdown(f"- **Filename:** `{rec.filename}`")
                st.markdown(f"- **Full Path:** `{rec.path}`")
                st.markdown(f"- **MFT Record Index:** `{rec.record_number}` (Sequence: `{rec.sequence_number}`)")
                st.markdown(f"- **Flags:** `0x0000` (<span class='badge-del'>Deleted / Unallocated</span>)", unsafe_allow_html=True)
                st.markdown(f"- **File Size:** `{rec.file_size}` bytes (Allocated: `{rec.allocated_size}` bytes)")
                st.markdown(f"- **Data Stream Type:** `{'Resident in MFT Record' if rec.is_resident else 'Non-Resident Runlist'}`")
                st.markdown(f"- **Source Artifact:** `{rec.source_artifact}`")

            with col_meta2:
                st.subheader("Timestamps Breakdown")
                ts_data = {
                    "Attribute": [
                        "$STANDARD_INFORMATION (0x10)", "", "", "",
                        "$FILE_NAME (0x30)", "", "", ""
                    ],
                    "Timestamp Type": [
                        "Created", "Modified", "MFT Modified", "Accessed",
                        "Created", "Modified", "MFT Modified", "Accessed"
                    ],
                    "Value (UTC)": [
                        rec.si_created.strftime("%Y-%m-%d %H:%M:%S UTC") if rec.si_created else "unknown",
                        rec.si_modified.strftime("%Y-%m-%d %H:%M:%S UTC") if rec.si_modified else "unknown",
                        rec.si_mft_modified.strftime("%Y-%m-%d %H:%M:%S UTC") if rec.si_mft_modified else "unknown",
                        rec.si_accessed.strftime("%Y-%m-%d %H:%M:%S UTC") if rec.si_accessed else "unknown",
                        rec.fn_created.strftime("%Y-%m-%d %H:%M:%S UTC") if rec.fn_created else "unknown",
                        rec.fn_modified.strftime("%Y-%m-%d %H:%M:%S UTC") if rec.fn_modified else "unknown",
                        rec.fn_mft_modified.strftime("%Y-%m-%d %H:%M:%S UTC") if rec.fn_mft_modified else "unknown",
                        rec.fn_accessed.strftime("%Y-%m-%d %H:%M:%S UTC") if rec.fn_accessed else "unknown",
                    ],
                }
                st.dataframe(pd.DataFrame(ts_data), use_container_width=True, hide_index=True)

            if rec.resident_data:
                st.subheader("Resident Data Hex & ASCII Preview (MFT Slack / Stream)")
                st.markdown(f'<div class="hex-display">{rec.hex_preview}</div>', unsafe_allow_html=True)

# -------------------------------------------------------------
# TAB 4: Recovery & Hash Verification
# -------------------------------------------------------------
with tabs[3]:
    st.header("4. Content Recovery & Cryptographic Verification")
    st.markdown("""
    Attempt bitstream extraction of deleted file content to an isolated output directory.
    Verify whether recovered bytes match known ground-truth hash.
    """)

    if not st.session_state.records:
        st.warning("Please load an evidence image in Tab 1 first.")
    else:
        col_rec1, col_rec2 = st.columns([1, 1])

        with col_rec1:
            st.subheader("Recovery Configuration")
            deleted_options = [r.filename for r in st.session_state.records.values() if not r.in_use]
            if not deleted_options:
                deleted_options = ["None"]
            target_selection = st.selectbox("Target Deleted File", deleted_options, index=0)
            
            gt_default = "evidence/ground_truth.json" if os.path.exists("evidence/ground_truth.json") else ""
            gt_path = st.text_input("Ground Truth JSON Path", value=gt_default)

            recover_btn = st.button("Attempt Content Recovery & Validate", type="primary")

        with col_rec2:
            st.subheader("Cryptographic Validation Outcome")
            if recover_btn and target_selection != "None":
                target_rec = None
                for r in st.session_state.records.values():
                    if r.filename == target_selection and not r.in_use:
                        target_rec = r
                        break

                if target_rec:
                    gt_data = None
                    if gt_path and os.path.exists(gt_path):
                        gt_full = load_ground_truth(gt_path)
                        gt_data = gt_full.get("target_file") if "target_file" in gt_full else gt_full

                    res = attempt_recovery(
                        parser=st.session_state.parser,
                        record=target_rec,
                        case_id=st.session_state.case_record.case_id if st.session_state.case_record else "CASE-DEFAULT",
                        ground_truth_record=gt_data,
                    )
                    st.session_state.recovery_result = res

            if st.session_state.recovery_result:
                r = st.session_state.recovery_result
                if r.status == "MATCH":
                    st.markdown("<span class='badge-match'>CRYPTOGRAPHIC MATCH</span>", unsafe_allow_html=True)
                    st.success("Recovered SHA-256 matches staged ground-truth baseline perfectly!")
                elif r.status == "MISMATCH":
                    st.error("CRYPTOGRAPHIC MISMATCH: Recovered content differs from baseline.")
                else:
                    st.warning(f"STATUS: {r.status}")

                st.markdown(f"- **Recovered File:** `{r.recovered_path or 'not recoverable in this test'}`")
                st.markdown(f"- **Size Extracted:** `{r.recovered_size}` bytes")
                st.markdown(f"- **Recovered SHA-256:**\n  `{r.recovered_sha256 or 'not available'}`")
                st.markdown(f"- **Baseline SHA-256:**\n  `{r.ground_truth_sha256 or 'not provided'}`")
                st.info(f"**Examiner Notes:** {r.investigative_notes}")

                if r.recovered_path and os.path.exists(r.recovered_path):
                    with open(r.recovered_path, "rb") as rf:
                        bytes_data = rf.read()
                    st.download_button(
                        label="Download Recovered File",
                        data=bytes_data,
                        file_name=os.path.basename(r.recovered_path),
                        mime="application/octet-stream",
                    )

# -------------------------------------------------------------
# TAB 5: Chronological Timeline
# -------------------------------------------------------------
with tabs[4]:
    st.header("5. Chronological Forensic Timeline")
    st.markdown("""
    Timeline reconstructed strictly from empirical file system timestamps.
    Includes both user-level (`$STANDARD_INFORMATION`) and filesystem-level (`$FILE_NAME`) times.
    """)

    if not st.session_state.timeline_events:
        st.info("No timeline events generated yet. Load evidence image in Tab 1.")
    else:
        del_only = st.checkbox("Show Only Deleted File Events", value=False)
        events = [e for e in st.session_state.timeline_events if (not del_only or e.allocation_status != "Allocated")]

        st.caption(f"Displaying {len(events)} chronological events:")
        tbl_data = format_timeline_table(events)
        st.dataframe(pd.DataFrame(tbl_data), use_container_width=True, hide_index=True)

# -------------------------------------------------------------
# TAB 6: Case Report & Audit
# -------------------------------------------------------------
with tabs[5]:
    st.header("6. Forensic Case Report Generation")
    st.markdown("""
    Generate an audit-compliant case report covering all 8 curriculum criteria.
    Reports use print-ready CSS for direct PDF export via browser print.
    """)

    if not st.session_state.case_record:
        st.warning("Please initialize case and evidence in Tab 1.")
    else:
        gen_rep_btn = st.button("Generate HTML Forensic Case Report", type="primary")

        target_file_record = None
        for r in st.session_state.records.values():
            if r.filename == "BUDGET_DRAFT.txt":
                target_file_record = r
                break

        if gen_rep_btn:
            rep_path = generate_case_report(
                case_record=st.session_state.case_record,
                target_record=target_file_record,
                all_records=list(st.session_state.records.values()),
                recovery_result=st.session_state.recovery_result,
                timeline_events=st.session_state.timeline_events,
            )
            st.success(f"Report generated successfully: `{rep_path}`")

            with open(rep_path, "r", encoding="utf-8") as f:
                html_text = f.read()

            st.download_button(
                label="Download Forensic Case Report (HTML)",
                data=html_text,
                file_name=os.path.basename(rep_path),
                mime="text/html",
            )

            st.divider()
            st.subheader("Report Live Preview")
            st.components.v1.html(html_text, height=800, scrolling=True)
