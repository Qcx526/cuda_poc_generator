@echo off
call "D:/Microsoft Visual Studio/18/Community/VC/Auxiliary/Build/vcvars64.bat" >nul 2>&1
cl /nologo /O2 /EHsc ..\..\tools\driver\nvapi_call.cpp /Fe:nvapi_call.exe /Fo:nvapi_call.obj
