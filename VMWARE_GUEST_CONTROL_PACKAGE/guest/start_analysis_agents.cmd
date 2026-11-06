@echo off
rem OS操作とGhidra解析の二つの受付を起動する。重複は各プロセスのMutexで防ぐ。
start "" /b "C:\Users\Public\r_AKanaly\runtime\python\pythonw.exe" "%~dp0analysis_agent.py" --root "%~dp0.." --role os
start "" /b "C:\Users\Public\r_AKanaly\runtime\python\pythonw.exe" "%~dp0analysis_agent.py" --root "%~dp0.." --role ghidra
