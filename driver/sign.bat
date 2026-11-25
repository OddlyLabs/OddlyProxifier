@echo off
rem Test-signs OddlyDrv.sys.   sign.bat <certificate.pfx> <password>
rem
rem A test-signed driver only loads on a machine that trusts the certificate
rem and runs with "bcdedit /set testsigning on". A release needs an EV
rem certificate and Microsoft attestation signing instead.
if "%~2"=="" (echo usage: sign.bat ^<certificate.pfx^> ^<password^> & exit /b 2)
set SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe
if not exist "%SIGNTOOL%" (echo signtool.exe not found: install the Windows SDK & exit /b 1)
"%SIGNTOOL%" sign /fd SHA256 /f "%~1" /p "%~2" "%~dp0OddlyDrv.sys"
if errorlevel 1 (echo SIGN_FAILED & exit /b 1)
echo DRIVER_SIGN_OK
