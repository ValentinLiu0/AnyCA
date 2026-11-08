@echo off
rem SPDX-License-Identifier: MIT
rem
rem SPDX-FileCopyrightText: 2026 Valentin Liu (LIU, YUANCHEN) <valentinliu@icloud.com>

setlocal

rem Configure and build AnyCA for Windows x86_64 with the Visual Studio
rem generator and vcpkg.  Run this script from "Developer Command Prompt for
rem VS" (or any shell where cl.exe is on PATH).
rem
rem usage: build-windows-x86_64-vs.bat [-h] [cmake configure arguments...]
rem
rem environment:
rem   VCPKG_ROOT   vcpkg installation (fallback: VCPKG_INSTALLATION_ROOT)
rem   BUILD_TYPE   build configuration (default: Release)
rem   BUILD_DIR    build directory (default: <repo>\build-windows-x86_64-vs)
rem   BUILD_JOBS   parallel build jobs (default: NUMBER_OF_PROCESSORS)

if /i "%~1"=="-h" goto :usage
if /i "%~1"=="--help" goto :usage

for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"
if not defined BUILD_DIR set "BUILD_DIR=%ROOT%\build-windows-x86_64-vs"
if not defined BUILD_TYPE set "BUILD_TYPE=Release"
if not defined BUILD_JOBS set "BUILD_JOBS=%NUMBER_OF_PROCESSORS%"

where cl >nul 2>&1
if errorlevel 1 (
    echo error: cl.exe not found in PATH; start "Developer Command Prompt for VS" and run this script from there 1>&2
    exit /b 1
)

where cmake >nul 2>&1
if errorlevel 1 (
    echo error: cmake not found in PATH; install CMake 4.3 or newer and put it on PATH 1>&2
    exit /b 1
)

rem The project requires CMake 4.3, which is newer than the copy bundled with
rem most Visual Studio versions.
set "CMAKE_VERSION="
for /f "tokens=3" %%V in ('cmake --version 2^>nul') do if not defined CMAKE_VERSION set "CMAKE_VERSION=%%V"
if not defined CMAKE_VERSION (
    echo error: cannot determine the cmake version 1>&2
    exit /b 1
)
for /f "tokens=1,2 delims=." %%A in ("%CMAKE_VERSION%") do (
    set "CMAKE_MAJOR=%%A"
    set "CMAKE_MINOR=%%B"
)
if not defined CMAKE_MINOR set "CMAKE_MINOR=0"
if %CMAKE_MAJOR% LSS 4 (
    echo error: cmake %CMAKE_VERSION% is too old; CMake 4.3 or newer is required ^(the copy bundled with Visual Studio is older^) 1>&2
    exit /b 1
)
if %CMAKE_MAJOR% EQU 4 if %CMAKE_MINOR% LSS 3 (
    echo error: cmake %CMAKE_VERSION% is too old; CMake 4.3 or newer is required ^(the copy bundled with Visual Studio is older^) 1>&2
    exit /b 1
)

if not defined VCPKG_ROOT if defined VCPKG_INSTALLATION_ROOT set "VCPKG_ROOT=%VCPKG_INSTALLATION_ROOT%"
if not defined VCPKG_ROOT (
    echo error: VCPKG_ROOT is not set; set it to your vcpkg checkout, e.g. set "VCPKG_ROOT=C:\src\vcpkg" 1>&2
    exit /b 1
)
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
    echo error: vcpkg toolchain file not found: %VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake 1>&2
    exit /b 1
)
if not exist "%VCPKG_ROOT%\vcpkg.exe" (
    echo error: vcpkg.exe not found in %VCPKG_ROOT%; run "%VCPKG_ROOT%\bootstrap-vcpkg.bat" first 1>&2
    exit /b 1
)

echo building AnyCA for windows-x86_64 (Visual Studio, vcpkg) in %BUILD_DIR%

rem Let cmake pick the newest installed Visual Studio generator.  -A x64
rem selects the platform and with it the x64-windows vcpkg triplet.
cmake -S "%ROOT%" -B "%BUILD_DIR%" -A x64 ^
    -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" ^
    -DVCPKG_TARGET_TRIPLET=x64-windows ^
    %*
if errorlevel 1 (
    echo error: cmake configure failed; install the project dependencies with vcpkg and pass -DCMAKE_PREFIX_PATH=... for libraries that are not in vcpkg 1>&2
    exit /b 1
)

cmake --build "%BUILD_DIR%" --config "%BUILD_TYPE%" --parallel "%BUILD_JOBS%"
if errorlevel 1 (
    echo error: build failed 1>&2
    exit /b 1
)

exit /b 0

:usage
echo usage: build-windows-x86_64-vs.bat [cmake configure arguments...]
echo.
echo Configure and build AnyCA for Windows x86_64 with the Visual Studio
echo generator and vcpkg.  Run this script from "Developer Command Prompt
echo for VS" (or any shell where cl.exe is on PATH).
echo.
echo environment:
echo   VCPKG_ROOT   vcpkg installation (fallback: VCPKG_INSTALLATION_ROOT)
echo   BUILD_TYPE   build configuration (default: Release)
echo   BUILD_DIR    build directory (default: ^<repo^>\build-windows-x86_64-vs)
echo   BUILD_JOBS   parallel build jobs (default: NUMBER_OF_PROCESSORS)
exit /b 0
