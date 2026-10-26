<#
.SYNOPSIS
    Creates a native Windows NTFS Virtual Hard Disk (VHD) for forensic deleted file analysis.
.DESCRIPTION
    Requires Administrative privileges. Automates diskpart and PowerShell to:
    1. Create a 30MB fixed VHD (disk_scenario.vhd).
    2. Partition and format with Windows NTFS.
    3. Stage control files (README.txt, MEETING_NOTES.txt).
    4. Stage target file (BUDGET_DRAFT.txt) and record its original SHA-256 hash.
    5. Delete BUDGET_DRAFT.txt via standard Windows shell command.
    6. Detach VHD and compute master cryptographic hashes.
    7. Create a forensic working copy clone for analysis.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\create_windows_vhd.ps1
#>

[CmdletBinding()]
param(
    [string]$VhdPath = "$PSScriptRoot\..\evidence\disk_scenario.vhd",
    [string]$WorkingCopyPath = "$PSScriptRoot\..\evidence\disk_scenario_working.vhd",
    [string]$GroundTruthPath = "$PSScriptRoot\..\evidence\vhd_ground_truth.json"
)

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges to attach and format VHDs in Windows."
    Write-Warning "Please right-click PowerShell and select 'Run as Administrator', or use 'scripts/create_test_image.py' for unprivileged synthetic disk image creation."
    exit 1
}

$evidenceDir = Split-Path -Parent (Resolve-Path -Path (Split-Path -Parent $VhdPath) -ErrorAction SilentlyContinue)
if (-not (Test-Path $evidenceDir)) {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
}

$VhdResolved = [System.IO.Path]::GetFullPath($VhdPath)
$WorkingResolved = [System.IO.Path]::GetFullPath($WorkingCopyPath)
$GroundTruthResolved = [System.IO.Path]::GetFullPath($GroundTruthPath)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Windows Forensics Lab: Native VHD Scenario Preparation   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Target VHD: $VhdResolved"

# Cleanup existing VHD if present
if (Test-Path $VhdResolved) {
    Write-Host "[*] Detaching and removing previous VHD..."
    $cleanupScript = @"
select vdisk file="$VhdResolved"
detach vdisk
"@
    $cleanupScript | diskpart | Out-Null
    Remove-Item -Path $VhdResolved -Force -ErrorAction SilentlyContinue
}

# 1. Diskpart script to create and attach VHD
Write-Host "[*] Creating 30MB fixed NTFS VHD via diskpart..."
$dpCreateScript = @"
create vdisk file="$VhdResolved" maximum=30 type=fixed
select vdisk file="$VhdResolved"
attach vdisk
clean
convert mbr
create partition primary
format fs=ntfs quick label="FORENSIC_LAB"
assign
"@

$dpOutput = $dpCreateScript | diskpart
Write-Host $dpOutput

# Wait for volume to mount and find drive letter
Start-Sleep -Seconds 3
$volume = Get-Volume -FileSystemLabel "FORENSIC_LAB" -ErrorAction SilentlyContinue
if (-not $volume -or -not $volume.DriveLetter) {
    Write-Error "Failed to locate mounted FORENSIC_LAB volume drive letter."
    exit 1
}

$drive = "$($volume.DriveLetter):\"
Write-Host "[+] Mounted forensic volume at: $drive" -ForegroundColor Green

# 2. Populate Files
Write-Host "[*] Populating staged synthetic evidence files..."
$readmePath = Join-Path $drive "README.txt"
$notesPath = Join-Path $drive "MEETING_NOTES.txt"
$budgetPath = Join-Path $drive "BUDGET_DRAFT.txt"

$readmeContent = @"
Digital Forensics Laboratory - Controlled Case Scenario
File System: Microsoft Windows NTFS
Objective: Verify metadata persistence and deleted file recovery.
"@
Set-Content -Path $readmePath -Value $readmeContent -Encoding utf8

$notesContent = @"
Project Titan Executive Meeting - October 2026
Attendees: J. Doe, A. Smith, R. Vance
Notes: Preliminary budget drafts presented and discussed.
"@
Set-Content -Path $notesPath -Value $notesContent -Encoding utf8

$budgetContent = @"
CONFIDENTIAL & PRIVILEGED - ACME CORP 2026 FINANCIAL RESTRUCTURING DRAFT
Date: October 24, 2026
Author: J. Doe, Director of Corporate Finance
Target Allocation: Q4 Redundancy Reserve: $1,450,000 USD
Project Titan Contingency Funds: $820,000 USD
Notice: Preliminary draft scheduled for permanent purge prior to regulatory audit.
"@
Set-Content -Path $budgetPath -Value $budgetContent -Encoding utf8

# Record Ground Truth before deletion
$budgetBytes = [System.IO.File]::ReadAllBytes($budgetPath)
$budgetHash = (Get-FileHash -Path $budgetPath -Algorithm SHA256).Hash.ToLower()
$budgetMd5 = (Get-FileHash -Path $budgetPath -Algorithm MD5).Hash.ToLower()

$groundTruth = @{
    case_name = "Windows Native VHD Scenario"
    scenario = "Native Windows diskpart NTFS fixed VHD"
    target_file = @{
        filename = "BUDGET_DRAFT.txt"
        original_size_bytes = $budgetBytes.Length
        sha256 = $budgetHash
        md5 = $budgetMd5
        deletion_method = "Remove-Item (Standard Windows Shell Unlink)"
    }
    control_files = @(
        @{ filename = "README.txt"; status = "Allocated" }
        @{ filename = "MEETING_NOTES.txt"; status = "Allocated" }
    )
}
$groundTruth | ConvertTo-Json -Depth 5 | Set-Content -Path $GroundTruthResolved -Encoding utf8
Write-Host "[+] Ground truth recorded: $GroundTruthResolved" -ForegroundColor Green
Write-Host "    Target SHA-256: $budgetHash"

# 3. Perform Deletion
Start-Sleep -Seconds 2
Write-Host "[*] Performing staged deletion of BUDGET_DRAFT.txt..." -ForegroundColor Yellow
Remove-Item -Path $budgetPath -Force
Write-Host "[+] File deleted from file system."

# Flush file system buffers
Start-Sleep -Seconds 2

# 4. Detach VHD
Write-Host "[*] Detaching VHD..."
$dpDetachScript = @"
select vdisk file="$VhdResolved"
detach vdisk
"@
$dpDetachScript | diskpart | Out-Null
Start-Sleep -Seconds 2

# 5. Compute Master Hash and Create Working Copy
Write-Host "[*] Calculating Master Image SHA-256..."
$masterSha256 = (Get-FileHash -Path $VhdResolved -Algorithm SHA256).Hash.ToLower()
Write-Host "    Master SHA-256: $masterSha256" -ForegroundColor Green

Write-Host "[*] Creating forensic Working Copy: $WorkingResolved"
Copy-Item -Path $VhdResolved -Destination $WorkingResolved -Force
$workingSha256 = (Get-FileHash -Path $WorkingResolved -Algorithm SHA256).Hash.ToLower()

if ($masterSha256 -eq $workingSha256) {
    Write-Host "[+] Verified: Working copy is identical clone of Master (100% Hash Match)" -ForegroundColor Green
} else {
    Write-Error "Clone verification failed! Hashes do not match."
    exit 1
}

Write-Host "`n[+] Scenario preparation complete! You can now analyze the VHD with:" -ForegroundColor Cyan
Write-Host "    python src/cli.py run-all --image evidence/disk_scenario_working.vhd --ground-truth evidence/vhd_ground_truth.json" -ForegroundColor White
