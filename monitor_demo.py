#!/usr/bin/env python3
"""
Simple monitoring script to check the Security Monitor status
"""

import requests
import time
import json
from datetime import datetime

# API endpoint
API_URL = "http://localhost:8001"

def check_status():
    """Check current monitoring status"""
    try:
        # Get status
        response = requests.get(f"{API_URL}/api/status")
        if response.status_code == 200:
            data = response.json()
            print(f"\n📊 Status at {datetime.now().strftime('%H:%M:%S')}")
            print("=" * 40)
            print(f"Capture Status: {data['capture_status']}")
            print(f"Threats Detected: {data['threats_detected']}")
            print(f"Packets Analyzed: {data['packets_analyzed']}")
            print(f"Anomalies Found: {data['anomalies_detected']}")
            
            # Alert if threats found
            if data['threats_detected'] > 0:
                print("\n⚠️  ALERT: Threats detected!")
            
            if data['anomalies_detected'] > 0:
                print("\n🔍 ALERT: Anomalies detected!")
                
        else:
            print(f"❌ Error: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to API. Is the server running?")
    except Exception as e:
        print(f"❌ Error: {e}")

def check_health():
    """Check system health"""
    try:
        response = requests.get(f"{API_URL}/health")
        if response.status_code == 200:
            data = response.json()
            print(f"\n💚 System Health: {data['status'].upper()}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
    except:
        pass

def main():
    print("🚀 Starting Security Monitor Dashboard")
    print(f"📍 Monitoring API at {API_URL}")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            check_health()
            check_status()
            print("\n" + "-" * 40)
            print("Refreshing in 5 seconds...")
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\n\n✋ Monitoring stopped")

if __name__ == "__main__":
    main()