@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS oddly_proxy.c /Fe:OddlyProxy.exe ws2_32.lib
if errorlevel 1 (echo BUILD_FAILED & exit /b 1)
echo BUILD_OK
