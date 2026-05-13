#!/usr/bin/env python3
"""
Quick Start Script for AI Intrusion Detection System
Generates threat data and runs the system
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{text}{Colors.END}\n")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def check_python_version():
    """Verify Python 3.8+"""
    if sys.version_info < (3, 8):
        print_error("Python 3.8+ required")
        sys.exit(1)
    print_success(f"Python {sys.version.split()[0]} detected")

def check_dependencies():
    """Check if required packages are installed"""
    print_header("🔍 Checking Dependencies")
    
    required = ['numpy', 'pandas', 'scikit-learn', 'streamlit', 'fastapi']
    missing = []
    
    for pkg in required:
        try:
            __import__(pkg)
            print_success(f"{pkg} installed")
        except ImportError:
            missing.append(pkg)
            print_warning(f"{pkg} not found")
    
    if missing:
        print_error(f"Missing packages: {', '.join(missing)}")
        print_info("Run: pip install -r requirements.txt")
        return False
    
    return True

def generate_threat_data():
    """Generate realistic threat dataset"""
    print_header("📊 Generating Threat Dataset")
    
    try:
        from src.threat_generator import ThreatScenarioGenerator
        
        print_info("Generating 5,000 sample packets...")
        gen = ThreatScenarioGenerator(random_seed=42)
        df = gen.generate_mixed_dataset(5000)
        
        # Ensure data directory exists
        os.makedirs('data', exist_ok=True)
        
        # Save dataset
        output_path = 'data/realistic_threats.csv'
        gen.save_to_csv(df, output_path)
        print_success(f"Dataset saved: {output_path}")
        
        return True
    except Exception as e:
        print_error(f"Failed to generate data: {e}")
        return False

def run_api_server():
    """Start FastAPI server"""
    print_header("🚀 Starting FastAPI Server")
    
    try:
        print_info("FastAPI server running at http://localhost:8000")
        print_info("API docs at http://localhost:8000/docs")
        subprocess.run([
            sys.executable, '-m', 'uvicorn',
            'src.ids_api_server:app',
            '--host', '0.0.0.0',
            '--port', '8000',
            '--reload'
        ])
    except KeyboardInterrupt:
        print_warning("\nServer stopped")
    except Exception as e:
        print_error(f"Failed to start server: {e}")

def run_streamlit_dashboard():
    """Start Streamlit dashboard"""
    print_header("📊 Starting Streamlit Dashboard")
    
    try:
        print_info("Dashboard running at http://localhost:8501")
        subprocess.run([
            sys.executable, '-m', 'streamlit',
            'run', 'streamlit_app/app.py',
            '--server.port=8501'
        ])
    except KeyboardInterrupt:
        print_warning("\nDashboard stopped")
    except Exception as e:
        print_error(f"Failed to start dashboard: {e}")

def run_docker_compose():
    """Start with Docker Compose"""
    print_header("🐳 Starting Docker Container")
    
    try:
        print_info("Building and starting services...")
        result = subprocess.run(['docker-compose', 'up', '-d'], capture_output=True, text=True)
        
        if result.returncode == 0:
            print_success("Services started successfully")
            print_info("FastAPI: http://localhost:8000")
            print_info("Streamlit: http://localhost:8501")
            print_info("Grafana: http://localhost:3000 (admin/admin123)")
            print_info("Prometheus: http://localhost:9090")
        else:
            print_error(f"Docker Compose failed: {result.stderr}")
            return False
        
        return True
    except Exception as e:
        print_error(f"Docker not found or error: {e}")
        return False

def run_threat_simulator():
    """Run threat detection simulator"""
    print_header("⚔️ Running Threat Simulator")
    
    try:
        from src.threat_generator import ThreatScenarioGenerator, RealWorldScenarioSimulator
        
        print_info("Simulating attacks...")
        simulator = RealWorldScenarioSimulator()
        
        # Simulate different attacks
        print("\n1️⃣  Simulating DDoS attack...")
        ddos_df = simulator.simulate_ddos_campaign(duration_minutes=1)
        print_success(f"Generated {len(ddos_df)} DDoS packets")
        
        print("\n2️⃣  Simulating night attack...")
        night_df = simulator.simulate_night_attack(hours=1)
        print_success(f"Generated {len(night_df)} night attack packets")
        
        return True
    except Exception as e:
        print_error(f"Simulation failed: {e}")
        return False

def show_menu():
    """Display interactive menu"""
    print_header("🛡️ AI Intrusion Detection System")
    print(f"Version: 1.0.0")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n" + "="*50)
    print("\n📋 Select an option:\n")
    print("  1️⃣  Generate Threat Dataset")
    print("  2️⃣  Run API Server Only")
    print("  3️⃣  Run Streamlit Dashboard Only")
    print("  4️⃣  Run with Docker Compose (Full Stack)")
    print("  5️⃣  Run Threat Simulator")
    print("  6️⃣  Test API Endpoints")
    print("  7️⃣  View System Status")
    print("  8️⃣  Exit\n")

def test_api():
    """Test API endpoints"""
    print_header("🧪 Testing API Endpoints")
    
    try:
        import requests
        import json
        
        base_url = "http://localhost:8000"
        
        # Test health endpoint
        print_info("Testing health endpoint...")
        resp = requests.get(f"{base_url}/api/v1/health", timeout=5)
        if resp.status_code == 200:
            print_success("✅ Health check passed")
        
        # Test single prediction
        print_info("Testing prediction endpoint...")
        payload = {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_length": 1500,
            "pkt_count": 5,
            "bytes": 75000,
            "duration": 30.5,
            "rate": 0.16
        }
        
        resp = requests.post(f"{base_url}/api/v1/predict", json=payload, timeout=5)
        if resp.status_code == 200:
            result = resp.json()
            print_success(f"Prediction: {result['prediction']} (Confidence: {result['confidence']:.2%})")
        
        # Get alerts
        print_info("Fetching alerts...")
        resp = requests.get(f"{base_url}/api/v1/alerts", timeout=5)
        if resp.status_code == 200:
            alerts = resp.json()
            print_success(f"Retrieved {alerts['total_alerts']} alerts")
        
    except Exception as e:
        print_error(f"API test failed: {e}")
        print_warning("Make sure API server is running on http://localhost:8000")

def show_status():
    """Show system status"""
    print_header("🖥️ System Status")
    
    try:
        import requests
        
        services = {
            "FastAPI": "http://localhost:8000/api/v1/health",
            "Streamlit": "http://localhost:8501",
            "Grafana": "http://localhost:3000",
            "Prometheus": "http://localhost:9090",
        }
        
        for service, url in services.items():
            try:
                resp = requests.get(url, timeout=2)
                if resp.status_code in [200, 301, 302]:
                    print_success(f"{service} - Running")
                else:
                    print_warning(f"{service} - Unreachable")
            except:
                print_warning(f"{service} - Not running")
        
        # Check Docker
        try:
            result = subprocess.run(['docker', 'ps'], capture_output=True, text=True)
            lines = result.stdout.count('\n') - 1
            print_success(f"Docker - {lines} containers running")
        except:
            print_warning("Docker - Not available")
        
    except Exception as e:
        print_error(f"Status check failed: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='AI Intrusion Detection System Quick Start')
    parser.add_argument('--mode', choices=['api', 'dashboard', 'docker', 'simulator', 'auto'],
                       help='Run mode')
    parser.add_argument('--generate-data', action='store_true', help='Generate threat data')
    parser.add_argument('--test', action='store_true', help='Test API endpoints')
    
    args = parser.parse_args()
    
    # Check Python version
    check_python_version()
    
    # If mode is specified, run directly
    if args.mode:
        if args.generate_data or args.mode == 'simulator':
            generate_threat_data()
        
        if args.mode == 'api':
            run_api_server()
        elif args.mode == 'dashboard':
            run_streamlit_dashboard()
        elif args.mode == 'docker':
            run_docker_compose()
        elif args.mode == 'simulator':
            run_threat_simulator()
        elif args.mode == 'auto':
            check_dependencies()
            generate_threat_data()
            run_docker_compose()
        
        return
    
    # If test flag is set
    if args.test:
        test_api()
        return
    
    # Interactive mode
    print_info("Starting Interactive Mode...")
    
    check_dependencies()
    
    while True:
        show_menu()
        choice = input("Enter your choice (1-8): ").strip()
        
        if choice == '1':
            generate_threat_data()
        elif choice == '2':
            run_api_server()
        elif choice == '3':
            run_streamlit_dashboard()
        elif choice == '4':
            run_docker_compose()
        elif choice == '5':
            run_threat_simulator()
        elif choice == '6':
            test_api()
        elif choice == '7':
            show_status()
        elif choice == '8':
            print_success("Goodbye!")
            break
        else:
            print_error("Invalid choice")

if __name__ == "__main__":
    main()
