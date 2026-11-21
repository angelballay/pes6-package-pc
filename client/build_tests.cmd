@echo off
rem Compila y corre las pruebas del verificador con las Build Tools de VS 2019 (x86, /MT), como HD Text.
rem Uso (con la ruta completa): client\build_tests.cmd
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars32.bat" >nul || exit /b 1
cd /d "%~dp0"
set OUT=..\build\client-vs2019
set M=vendor\monocypher-4.0.2
if not exist %OUT% mkdir %OUT%
cl /nologo /O2 /MT /W4 /EHsc /utf-8 /DWIN32_LEAN_AND_MEAN /I. /I%M% tests\test_client.cpp pes6pkg_core.cpp pes6pkg_zip.cpp pes6pkg_win.cpp %M%\monocypher.c %M%\optional\monocypher-ed25519.c /Fo%OUT%\ /Fe%OUT%\test_client.exe /link winhttp.lib bcrypt.lib || exit /b 1
python -I ..\tool\run.py --test-keys vectors --out ..\build\vectors || exit /b 1
%OUT%\test_client.exe ..\build\vectors
exit /b %ERRORLEVEL%
