Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "    AI-Powered Intelligent Phishing Detection & Protection System" -ForegroundColor Green
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Starting FastAPI Backend on http://localhost:8000 ..." -ForegroundColor Yellow
Start-Process "http://localhost:8000"
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
