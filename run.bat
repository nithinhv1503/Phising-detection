@echo off
title AI Phishing Sentinel - Detection Server & Dashboard
echo ===================================================================
echo     AI-Powered Intelligent Phishing Detection & Protection System
echo ===================================================================
echo.
echo [*] Starting FastAPI Backend on http://localhost:8000 ...
echo [*] Opening Web Dashboard in default browser...
start http://localhost:8000
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
pause
