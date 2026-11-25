@echo off
rem Set WDKROOT to the Windows Driver Kit when it is not in the default place.
if not defined WDKROOT set "WDKROOT=C:\Program Files (x86)\Windows Kits"
set WDKINC=%WDKROOT%\Include\10.0.26100.0
set WDKLIB=%WDKROOT%\Lib\10.0.26100.0\km\x64
set SRCDIR=%~dp0

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%SRCDIR%"

cl /c /nologo /W4 /WX- /wd4324 /kernel /GS- /Gy /Zl /utf-8 /wd4996 ^
  /D _AMD64_ /D AMD64 /D _WIN64 /D NTDDI_VERSION=0x0A000000 /D _WIN32_WINNT=0x0A00 ^
  /I "%WDKINC%\km" /I "%WDKINC%\km\crt" /I "%WDKINC%\shared" /I "%WDKINC%\um" ^
  OddlyDrv.c
if errorlevel 1 (echo CL_FAILED & exit /b 1)

link /nologo /DRIVER /SUBSYSTEM:NATIVE,10.00 /MACHINE:X64 /OUT:OddlyDrv.sys /ENTRY:DriverEntry /INCREMENTAL:NO ^
  /LIBPATH:"%WDKLIB%" ntoskrnl.lib hal.lib fwpkclnt.lib wdmsec.lib BufferOverflowFastFailK.lib OddlyDrv.obj
if errorlevel 1 (echo LINK_FAILED & exit /b 1)

echo DRIVER_BUILD_OK
