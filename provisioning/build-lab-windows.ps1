# LAB-WINDOWS provisioner — FLARE-VM (Mandiant) on a clean Windows 10 VM.
# Run elevated. SNAPSHOT the VM before running. Network on during install only.
$ErrorActionPreference = "Stop"
Write-Host "[lab-windows] downloading FLARE-VM installer"
$dst = "$env:USERPROFILE\Desktop\flare-install.ps1"
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1', $dst)
Unblock-File $dst
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Write-Host "[lab-windows] installing default 136-package profile (Chocolatey) — this takes a while"
& $dst
Write-Host "[lab-windows] done. Capture installed set: choco list | Out-File installed.txt"
