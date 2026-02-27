"""
run.py - Server Entry Point
Run from project root: python run.py
"""
import subprocess
import sys
import os

os.chdir(os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.getcwd())

if __name__ == "__main__":
    subprocess.run([
        sys.executable, "-m", "uvicorn", "main:app",
        "--host", "0.0.0.0", "--port", "8000", "--reload"
    ])
