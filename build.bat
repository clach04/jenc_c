@echo off
rem jenc_c build without make (Windows).
rem Usage: build.bat [test|debug|clean]
rem Needs gcc (MinGW-w64) on PATH, e.g. strawberry-perl c\bin.
rem Run from the jenc_c directory.
setlocal

set CSTD=-std=c99 -Wall -Wextra -pedantic -Wno-attributes -D_POSIX_C_SOURCE=200809L
set CPP=-Isrc\openssh_shim -Isrc -Isrc\openssh-portable
set OPT=-O2
set LIBS=-lbcrypt

if "%1"=="clean" goto :clean
if "%1"=="debug" set OPT=-O2 -DJENC_DEBUG_SKIP_MAC

echo == vendored (warnings suppressed for upstream code)
gcc %OPT% %CPP% -w -c -o src\openssh-portable\rijndael.o src\openssh-portable\rijndael.c || goto :fail
gcc %OPT% %CPP% -w -c -o src\openssh-portable\openbsd-compat\sha2.o src\openssh-portable\openbsd-compat\sha2.c || goto :fail

echo == libjenc
gcc %CSTD% %OPT% %CPP% -c -o src\jenc.o src\jenc.c || goto :fail
gcc %CSTD% %OPT% %CPP% -c -o src\jenc_crypto.o src\jenc_crypto.c || goto :fail
ar rcs libjenc.a src\jenc.o src\jenc_crypto.o src\openssh-portable\rijndael.o src\openssh-portable\openbsd-compat\sha2.o || goto :fail

echo == jenc.exe
gcc %CSTD% %OPT% %CPP% -o jenc.exe src\jenc_crypt.c libjenc.a %LIBS% || goto :fail

if "%1"=="test" goto :test
if "%1"=="debug" goto :ok
goto :ok

:test
echo == test_vectors.exe
gcc %CSTD% %OPT% %CPP% -o test_vectors.exe tests\test_vectors.c libjenc.a %LIBS% || goto :fail
test_vectors.exe || goto :fail
goto :ok

:clean
del /q src\jenc.o src\jenc_crypto.o src\openssh-portable\rijndael.o src\openssh-portable\openbsd-compat\sha2.o libjenc.a jenc.exe test_vectors.exe 2>nul
echo cleaned
goto :eof

:ok
echo OK
endlocal
exit /b 0

:fail
echo BUILD FAILED
endlocal
exit /b 1
