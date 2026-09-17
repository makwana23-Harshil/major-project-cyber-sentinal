@echo off
echo ============================================
echo   CyberSentinel Pro - Starting Backend
echo ============================================
echo.
cd /d "%~dp0backend"
echo [1/2] Checking ML models...
python -c "import os; models=['sms_model.pkl','email_body_model.pkl','url_model.pkl']; missing=[m for m in models if not os.path.exists(os.path.join('models',m))]; exit(1 if missing else 0)" 2>nul
if %errorlevel% neq 0 (
    echo [2/2] Training ML models for first time...
    python models\train_models.py
) else (
    echo [2/2] ML models ready.
)
echo.
echo Starting Flask server on http://127.0.0.1:5000
echo Admin login: admin@cybersentinel.com / Admin@2024
echo.
echo Open frontend: %~dp0frontend\index.html
echo.
python app.py
pause
