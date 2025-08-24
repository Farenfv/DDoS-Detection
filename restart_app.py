#!/usr/bin/env python3
"""Restart the DDoS detection application with new code."""

import subprocess
import time
import requests
import psutil
import os
import signal

def kill_existing_processes():
    """Kill existing Python processes running the app."""
    print("Stopping existing processes...")
    
    # Find and kill processes using port 5000
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] == 'python.exe' and proc.info['cmdline']:
                cmdline = ' '.join(proc.info['cmdline'])
                if 'ddos_detection.py' in cmdline:
                    print(f"Killing process {proc.info['pid']}: {cmdline}")
                    proc.terminate()
                    proc.wait(timeout=5)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            pass
    
    time.sleep(2)

def start_new_process():
    """Start the new application process."""
    print("Starting new application...")
    
    # Change to the correct directory
    os.chdir(r'c:\Users\FM_Re\Desktop\DDoS-Detection-main')
    
    # Start the new process
    process = subprocess.Popen(
        ['python', 'ddos_detection.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )
    
    print(f"Started new process with PID: {process.pid}")
    return process

def test_application():
    """Test if the application is responding."""
    print("Testing application...")
    
    for i in range(10):
        try:
            response = requests.get('http://localhost:5000/test', timeout=2)
            if response.status_code == 200:
                print("✓ Application is running and responding")
                return True
        except:
            pass
        
        print(f"Waiting for application to start... ({i+1}/10)")
        time.sleep(2)
    
    print("✗ Application failed to start or respond")
    return False

def force_alternative_monitoring():
    """Force start alternative monitoring."""
    try:
        response = requests.post('http://localhost:5000/api/force-monitoring', timeout=5)
        if response.status_code == 200:
            print("✓ Alternative monitoring started")
            return True
        else:
            print(f"⚠ Failed to start alternative monitoring: {response.status_code}")
    except Exception as e:
        print(f"⚠ Error starting alternative monitoring: {e}")
    return False

if __name__ == "__main__":
    print("Restarting DDoS Detection Application...")
    
    # Step 1: Kill existing processes
    kill_existing_processes()
    
    # Step 2: Start new process
    process = start_new_process()
    
    # Step 3: Test application
    if test_application():
        # Step 4: Force alternative monitoring
        force_alternative_monitoring()
        print("\n✓ Application restarted successfully!")
        print("Open http://localhost:5000 to view the dashboard")
    else:
        print("\n✗ Application restart failed")
        if process:
            process.terminate()
