@echo off
echo Compiling PassAuth Simple Version...
javac PassAuthSimple.java

if %ERRORLEVEL% EQU 0 (
    echo Compilation successful!
    echo Running PassAuth Simple...
    java PassAuthSimple
) else (
    echo Compilation failed!
    pause
)
