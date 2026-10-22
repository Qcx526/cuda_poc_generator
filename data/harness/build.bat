@echo off
call "D:/Microsoft Visual Studio/18/Community/VC/Auxiliary/Build/vcvars64.bat" >nul 2>&1
cl /nologo /O2 /EHsc ..\..\tools\driver\shader_runner.cpp /Fe:shader_runner.exe /Fo:shader_runner.obj /link d3d9.lib d3dcompiler.lib user32.lib
