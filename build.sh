#!/bin/bash
set -e

echo "🚀 Building Political Event Management System..."

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

echo "✅ Build completed successfully!"
