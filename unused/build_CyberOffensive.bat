@echo off

REM # 1. Clean build folders
echo Cleaning build folders...
del /Q /S dist\*
del /Q /S build\*
if exist hash.txt del hash.txt

REM # 2. Package the executable using PyInstaller
echo Packaging executable...
pyinstaller --onefile --noconfirm --log-level ERROR Game\src\code\CyberOffensive.py

REM # 3. Calculate the SHA-256 hash of the EXE
echo Generating hash of CyberOffensive.exe
setlocal enabledelayedexpansion
set exe_hash=
for /f "skip=1 tokens=*" %%a in ('certutil -hashfile "dist\CyberOffensive.exe" SHA256') do (
    if not defined exe_hash set "exe_hash=%%a"
)
endlocal & set "exe_hash=%exe_hash%"
echo Pre-Embedding Hash: %exe_hash%

REM # 4. Create a resource file (hash.txt) with the pre-calculated hash
echo %exe_hash% > hash.txt
echo hash.txt content: %exe_hash%

REM # 5. Embed the hash into the EXE
echo Packaging with embedded hash...
pyinstaller --onefile --noconfirm --log-level ERROR --add-data "hash.txt;." --hidden-import "pkg_resources" --hidden-import "hashlib" Game\src\code\CyberOffensive.py

REM # 6. Recalculate the SHA-256 hash of the final EXE (to verify)
echo Recalculating hash of the final executable
setlocal enabledelayedexpansion
set final_hash=
for /f "skip=1 tokens=*" %%a in ('certutil -hashfile "dist\CyberOffensive.exe" SHA256') do (
    if not defined final_hash set "final_hash=%%a"
)
endlocal & set "final_hash=%final_hash%"
echo Final Hash: %final_hash%

REM # 7. Compare the initial and final hashes
if "%exe_hash%" == "%final_hash%" (
    echo The hashes match. Embedding was successful.
) else (
    echo WARNING: The hashes do not match. Something went wrong.
)

pause
