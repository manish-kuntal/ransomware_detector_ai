@echo off
title RansomShield - Installing Dependencies
color 0B
cls
echo.
echo  ============================================
echo   RansomShield AI - Dependency Installer
echo  ============================================
echo.
echo  Installing all required packages...
echo  (This may take 2-5 minutes)
echo.

python -m pip install --upgrade pip
python -m pip install numpy pandas scikit-learn xgboost watchdog psutil flask matplotlib seaborn

echo.
echo  ============================================
echo   Installation Complete!
echo   Ab start_detector.bat chalao
echo  ============================================
echo.
pause
