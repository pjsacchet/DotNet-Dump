@echo off

:: get fullpath for executable and run it as system
PsExec.exe -accepteula -s %CD%\DotNet-Dump.exe

:: run python script to output results to txt
CalcHash.exe
