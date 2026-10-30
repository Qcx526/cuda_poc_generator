@echo off
call "D:/Microsoft Visual Studio/18/Community/VC/Auxiliary/Build/vcvars64.bat" >nul 2>&1
cl /nologo /O2 /EHsc ..\..\tools\driver\drs_probe.cpp /Fe:drs_probe.exe /Fo:drs_probe.obj
