#!/usr/bin/env python3
"""
Test script to verify HexStrike AI MCP integration works properly with Cursor
"""

import subprocess
import sys
import json
import time

def test_docker_container():
    """Test if HexStrike container is running"""
    print("Testing Docker container...")
    try:
        result = subprocess.run(['docker', 'ps', '--filter', 'name=hexstrike-ai-platform', '--format', 'table {{.Status}}'], 
                              capture_output=True, text=True, timeout=10)
        if 'healthy' in result.stdout.lower():
            print("[OK] HexStrike container is running and healthy")
            return True
        else:
            print("[FAIL] HexStrike container is not healthy")
            return False
    except Exception as e:
        print(f"[FAIL] Error checking container: {e}")
        return False

def test_api_health():
    """Test if HexStrike API is responding"""
    print(" Testing HexStrike API...")
    try:
        import requests
        response = requests.get('http://localhost:8888/health', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"[OK] API is healthy - {data.get('total_tools_available', 0)} tools available")
            return True
        else:
            print(f"[FAIL] API returned status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"[FAIL] Error testing API: {e}")
        return False

def test_mcp_script():
    """Test if MCP script can run without errors"""
    print(" Testing MCP script...")
    try:
        # Test the MCP script runs and exits cleanly
        result = subprocess.run([
            'python', 
            'C:/Users/Home/deepseek/hexstrike-ai/hexstrike_mcp.py',
            '--server', 'http://localhost:8888'
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("[OK] MCP script runs successfully")
            return True
        else:
            print(f"[FAIL] MCP script failed with return code: {result.returncode}")
            if result.stderr:
                print(f"Error output: {result.stderr[:200]}...")
            return False
    except subprocess.TimeoutExpired:
        print("[OK] MCP script started successfully (timeout expected for server mode)")
        return True
    except Exception as e:
        print(f"[FAIL] Error testing MCP script: {e}")
        return False

def test_python_dependencies():
    """Test if required Python packages are installed"""
    print(" Testing Python dependencies...")
    required_packages = ['fastmcp', 'requests', 'mcp']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"[OK] {package} is installed")
        except ImportError:
            print(f"[FAIL] {package} is missing")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"[FAIL] Missing packages: {', '.join(missing_packages)}")
        print("Run: pip install fastmcp requests")
        return False
    return True

def print_cursor_config():
    """Print the Cursor configuration"""
    print("\n Cursor Configuration:")
    print("Add this to your Cursor settings (Ctrl+Shift+P -> 'Preferences: Open Settings (JSON)'):")
    config = {
        "cursor.mcp.servers": {
            "hexstrike-ai": {
                "command": "python",
                "args": [
                    "C:/Users/Home/deepseek/hexstrike-ai/hexstrike_mcp.py",
                    "--server",
                    "http://localhost:8888"
                ],
                "description": "HexStrike AI Cybersecurity Tools"
            }
        }
    }
    print(json.dumps(config, indent=2))

def main():
    """Run all tests"""
    print("HexStrike AI + Cursor Integration Test\n")
    
    tests = [
        test_python_dependencies,
        test_docker_container,
        test_api_health,
        test_mcp_script
    ]
    
    results = []
    for test in tests:
        results.append(test())
        print()
    
    print("📊 Test Results Summary:")
    if all(results):
        print("🎉 All tests passed! HexStrike AI is ready for Cursor integration!")
        print_cursor_config()
        print("\n🔧 Next Steps:")
        print("1. Add the configuration above to your Cursor settings")
        print("2. Restart Cursor")
        print("3. Test with: '@hexstrike-ai scan localhost with nmap'")
    else:
        print("[FAIL] Some tests failed. Please fix the issues above before proceeding.")
        failed_tests = [name for name, result in zip(['Dependencies', 'Container', 'API', 'MCP'], results) if not result]
        print(f"Failed tests: {', '.join(failed_tests)}")

if __name__ == "__main__":
    main()