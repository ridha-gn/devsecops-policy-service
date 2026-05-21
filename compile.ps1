# compile.ps1 — One-click compile script for the PFE LaTeX report
# Double-click this file in Windows Explorer, or run:  PowerShell -File compile.ps1

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Set-Location "$PSScriptRoot\rapport"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Compiling PFE Report..." -ForegroundColor Cyan
Write-Host "============================================================"

Write-Host "[1/4] First pdflatex pass..." -ForegroundColor Yellow
pdflatex -interaction=nonstopmode main.tex | Select-Object -Last 3

Write-Host "[2/4] BibTeX (citations)..." -ForegroundColor Yellow
bibtex main | Select-Object -Last 3

Write-Host "[3/4] Second pdflatex pass..." -ForegroundColor Yellow
pdflatex -interaction=nonstopmode main.tex | Select-Object -Last 3

Write-Host "[4/4] Third pdflatex pass (final)..." -ForegroundColor Yellow
pdflatex -interaction=nonstopmode main.tex | Select-Object -Last 3

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " DONE! Opening main.pdf..." -ForegroundColor Green
Write-Host "============================================================"

Start-Process "main.pdf"
