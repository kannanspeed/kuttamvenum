#!/bin/bash

echo "🚀 Political Event Management System - Deployment Script"
echo "========================================================"

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "❌ Not in a git repository. Please initialize git first:"
    echo "   git init"
    echo "   git add ."
    echo "   git commit -m 'Initial commit'"
    exit 1
fi

# Check if we have a remote repository
if ! git remote get-url origin &> /dev/null; then
    echo "❌ No remote repository found. Please add your GitHub repository:"
    echo "   git remote add origin <your-github-repo-url>"
    exit 1
fi

echo "✅ Git repository found"

# Check if all required files exist
required_files=("app.py" "requirements.txt" "runtime.txt" "render.yaml")
missing_files=()

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -ne 0 ]; then
    echo "❌ Missing required files: ${missing_files[*]}"
    exit 1
fi

echo "✅ All required files found"

# Check if templates and static directories exist
if [ ! -d "templates" ]; then
    echo "❌ templates/ directory not found"
    exit 1
fi

if [ ! -d "static" ]; then
    echo "❌ static/ directory not found"
    exit 1
fi

echo "✅ Templates and static directories found"

# Push to GitHub
echo "📤 Pushing to GitHub..."
git add .
git commit -m "Deploy to Render - $(date)"
git push origin main

echo ""
echo "🎉 Code pushed to GitHub successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Go to https://dashboard.render.com/"
echo "2. Click 'New +' and select 'Blueprint'"
echo "3. Connect your GitHub repository"
echo "4. Render will automatically detect render.yaml"
echo "5. Click 'Apply' to deploy"
echo ""
echo "🔑 Default admin credentials:"
echo "   Email: admin@political.com"
echo "   Password: admin123"
echo ""
echo "📧 Optional: Set up email notifications in Render environment variables"
echo "   MAIL_SERVER=smtp.gmail.com"
echo "   MAIL_PORT=587"
echo "   MAIL_USE_TLS=true"
echo "   MAIL_USERNAME=your-email@gmail.com"
echo "   MAIL_PASSWORD=your-app-password"
echo "   MAIL_DEFAULT_SENDER=your-email@gmail.com"
