#!/usr/bin/env python3
"""
EDR Server Easy Start Script
Script đơn giản để khởi động server với kiểm tra environment
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Kiểm tra phiên bản Python"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required!")
        print(f"Current version: {sys.version}")
        return False
    
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_requirements():
    """Kiểm tra requirements.txt"""
    requirements_file = Path("requirements.txt")
    
    if not requirements_file.exists():
        print("❌ requirements.txt not found!")
        return False
    
    print("✅ requirements.txt found")
    
    # Check if packages are installed
    try:
        import flask
        import flask_socketio
        import pyodbc
        print("✅ Core packages are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing package: {e}")
        print("💡 Run: pip install -r requirements.txt")
        return False

def check_database_config():
    """Kiểm tra cấu hình database"""
    env_file = Path(".env")
    
    if not env_file.exists():
        print("⚠️  .env file not found, using default config")
        return True
    
    print("✅ .env file found")
    return True

def create_directories():
    """Tạo các thư mục cần thiết"""
    directories = ["logs", "uploads", "backups"]
    
    for dir_name in directories:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"✅ Created/verified directory: {dir_name}")

def install_requirements():
    """Cài đặt requirements nếu cần"""
    try:
        print("📦 Installing requirements...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False

def main():
    """Main function"""
    print("🚀 EDR Server Startup Checker")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check/install requirements
    if not check_requirements():
        print("\n💡 Attempting to install requirements...")
        if not install_requirements():
            sys.exit(1)
    
    # Check database config
    check_database_config()
    
    # Create directories
    print("\n📁 Creating directories...")
    create_directories()
    
    print("\n🎯 All checks passed! Starting EDR Server...")
    print("=" * 50)
    
    # Start the server
    try:
        from run_server import main as run_server
        run_server()
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()