Write-Host "Starting AI-Driven Threat Intelligence Dashboard..." -ForegroundColor Green

# Start Backend
Write-Host "Starting Backend FastAPI Server on Port 8000..." -ForegroundColor Cyan
Start-Process "powershell.exe" -ArgumentList "-NoExit -Command `"cd backend; .\venv\Scripts\uvicorn main:app --reload`""

# Wait for backend to be ready
Start-Sleep -Seconds 5

# Start Frontend
Write-Host "Starting Frontend Streamlit App on Port 8501..." -ForegroundColor Cyan
Start-Process "powershell.exe" -ArgumentList "-NoExit -Command `"cd frontend; .\venv\Scripts\streamlit run app.py`""

Write-Host "Both services started successfully! Check Streamlit UI." -ForegroundColor Green
