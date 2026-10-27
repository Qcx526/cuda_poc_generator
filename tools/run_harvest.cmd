@echo off
REM Boot task: harvest any probe that was armed before the machine went down.
REM Run as SYSTEM at startup so it does not depend on anyone logging in.
cd /d "%~dp0.."
".venv\Scripts\python.exe" -m tools.harvest_probe --scan data\loop >> "data\loop\harvest.log" 2>&1
