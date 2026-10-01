@echo off
title RansomShield AI v2.0
color 0A
cls

echo.
echo  ============================================
echo   RansomShield AI v2.0
echo   Honeypot + Ensemble + SHAP Explainability
echo  ============================================
echo.
echo  Starting system...
echo.

:: Project folder
cd /d C:\Users\manis\ransomware_detector

:: Step 1 - Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python nahi mila!
    echo  python.org se install karo aur PATH mein add karo.
    pause
    exit
)

:: Step 2 - Check model file
if not exist "models\saved\best_model.pkl" (
    echo  [*] Model nahi mila - train kar raha hun...
    echo.
    python generate_dataset.py --mode synthetic --n 300
    python train_models.py
    echo.
    echo  [OK] Model ready!
    echo.
)

:: Step 3 - Create sandbox folder
if not exist "data\sandbox" mkdir data\sandbox

:: Step 4 - Start Dashboard
echo  [1/3] Dashboard start ho raha hai...
start "RansomShield Dashboard" cmd /k "cd /d C:\Users\manis\ransomware_detector && python dashboard\app.py --watch C:\Users\manis\ransomware_detector\data\sandbox"

:: Wait for Flask to start
timeout /t 5 /nobreak >nul

:: Step 5 - Open browser
echo  [2/3] Browser khul raha hai...
start http://127.0.0.1:5000

timeout /t 2 /nobreak >nul

:: Step 6 - Start demo simulation
echo  [3/3] Demo simulation shuru ho rahi hai...
echo.
echo  ============================================
echo   Browser mein localhost:5000 dekho!
echo   Score 0.7 cross karega = Alert fire hoga
echo   Band karna ho toh dono windows close karo
echo  ============================================
echo.
start "Demo Simulation" cmd /k "cd /d C:\Users\manis\ransomware_detector && timeout /t 3 /nobreak >nul && python main.py --watch C:\Users\manis\ransomware_detector\data\sandbox --demo"

echo  Sab kuch chal raha hai. Yeh window band kar sakte ho.
echo.
pause
