@echo off
echo 🚀 Political Event Management System - Deployment Script
echo ========================================================

REM Check if git is installed
git --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Git is not installed. Please install Git first.
    pause
    exit /b 1
)

REM Check if we're in a git repository
git rev-parse --git-dir >nul 2>&1
if errorlevel 1 (
    echo ❌ Not in a git repository. Please initialize git first:
    echo    git init
    echo    git add .
    echo    git commit -m "Initial commit"
    pause
    exit /b 1
)

REM Check if we have a remote repository
git remote get-url origin >nul 2>&1
if errorlevel 1 (
    echo ❌ No remote repository found. Please add your GitHub repository:
    echo    git remote add origin ^<your-github-repo-url^>
    pause
    exit /b 1
)

echo ✅ Git repository found

REM Check if all required files exist
if not exist "app.py" (
    echo ❌ app.py not found
    pause
    exit /b 1
)

if not exist "requirements.txt" (
    echo ❌ requirements.txt not found
    pause
    exit /b 1
)

if not exist "runtime.txt" (
    echo ❌ runtime.txt not found
    pause
    exit /b 1
)

if not exist "render.yaml" (
    echo ❌ render.yaml not found
    pause
    exit /b 1
)

echo ✅ All required files found

REM Check if templates and static directories exist
if not exist "templates" (
    echo ❌ templates/ directory not found
    pause
    exit /b 1
)

if not exist "static" (
    echo ❌ static/ directory not found
    pause
    exit /b 1
)

echo ✅ Templates and static directories found

REM Push to GitHub
echo 📤 Pushing to GitHub...
git add .
git commit -m "Deploy to Render - %date% %time%"
git push origin main

echo.
echo 🎉 Code pushed to GitHub successfully!
echo.
echo 📋 Next steps:
echo 1. Go to https://dashboard.render.com/
echo 2. Click 'New +' and select 'Blueprint'
echo 3. Connect your GitHub repository
echo 4. Render will automatically detect render.yaml
echo 5. Click 'Apply' to deploy
echo.
echo 🔑 Default admin credentials:
echo    Email: admin@political.com
echo    Password: admin123
echo.
echo 📧 Optional: Set up email notifications in Render environment variables
echo    MAIL_SERVER=smtp.gmail.com
echo    MAIL_PORT=587
echo    MAIL_USE_TLS=true
echo    MAIL_USERNAME=your-email@gmail.com
echo    MAIL_PASSWORD=your-app-password
echo    MAIL_DEFAULT_SENDER=your-email@gmail.com

pause
