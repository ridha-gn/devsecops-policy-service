@echo off
REM ============================================================
REM  build.bat — Compile the PFE LaTeX report locally
REM  Run this from the rapport\ directory:
REM    cd rapport
REM    ..\build.bat
REM ============================================================

SET MAINFILE=main
SET OUTDIR=.

echo [1/4] First pdflatex pass...
pdflatex -interaction=nonstopmode -halt-on-error %MAINFILE%.tex
IF ERRORLEVEL 1 (
    echo.
    echo *** ERROR on first pdflatex pass. Check the log: %MAINFILE%.log
    pause
    exit /b 1
)

echo [2/4] BibTeX...
bibtex %MAINFILE%

echo [3/4] Second pdflatex pass (resolving citations)...
pdflatex -interaction=nonstopmode -halt-on-error %MAINFILE%.tex

echo [4/4] Third pdflatex pass (resolving references)...
pdflatex -interaction=nonstopmode -halt-on-error %MAINFILE%.tex

echo.
echo ============================================================
echo  Done! Output: rapport\%MAINFILE%.pdf
echo ============================================================

REM Open the PDF automatically
start "" "%MAINFILE%.pdf"
