#!/usr/bin/env python3
"""
Quick script to install ChromaDB and its dependencies
"""
import subprocess
import sys

def install_package(package):
    """Install a package using pip"""
    print(f"Installing {package}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✓ {package} installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install {package}: {e}")
        return False

def main():
    print("=" * 70)
    print("ChromaDB Installation Script")
    print("=" * 70)
    
    packages = [
        "chromadb==0.4.22",
        "sentence-transformers==2.3.1",
    ]
    
    success_count = 0
    for package in packages:
        if install_package(package):
            success_count += 1
        print()
    
    print("=" * 70)
    print(f"Installation complete: {success_count}/{len(packages)} packages installed")
    print("=" * 70)
    
    # Test import
    print("\nTesting ChromaDB import...")
    try:
        import chromadb
        print(f"✓ ChromaDB version: {chromadb.__version__}")
        print("✓ ChromaDB is ready to use!")
    except ImportError as e:
        print(f"✗ ChromaDB import failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
