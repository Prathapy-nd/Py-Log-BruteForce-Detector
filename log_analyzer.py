import sys
import os
from datetime import datetime

# --- Configuration ---
# Define the suspicious limit for failed login attempts
BRUTE_FORCE_THRESHOLD = 10 

# --- Core Analysis Logic ---
def analyze_logs(log_file_path):
    """
    Parses web server access logs to detect potential brute-force attacks 
    by counting 401 (Unauthorized) status codes per unique IP address.
    """
    
    # Use a dictionary to store IP (key) and failure count (value)
    failure_counts = {}
    
    # Check if the log file exists 
    if not os.path.exists(log_file_path):
        print(f"[ERROR] Log file not found at: {log_file_path}")
        return

    print(f"[*] Analyzing log file: {log_file_path}")
    print(f"[*] Threshold for detection set at: {BRUTE_FORCE_THRESHOLD} failed attempts.")
    print("-" * 50)
    
    try:
        # Open the file professionally using 'with'
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                parts = line.split()
                
                # Simple check to skip malformed lines
                if len(parts) < 9:
                    continue
                
                # Parsing: IP is at [0], Status Code is at [8] in standard format
                ip_address = parts[0]
                status_code = parts[8]
                
                # Detection Logic: Look for 401 Unauthorized errors
                if status_code == '401':
                    
                    # Counting: Get the current count and increment
                    current_count = failure_counts.get(ip_address, 0) + 1
                    failure_counts[ip_address] = current_count
                    
                    # Incident Check: Alert immediately if the threshold is met
                    if current_count == BRUTE_FORCE_THRESHOLD:
                        print("="*40)
                        print(f"!!! INCIDENT DETECTED: Threshold hit from {ip_address} (Attempt #{current_count})")
                        print("="*40)
                        
    except Exception as e:
        print(f"[FATAL] An error occurred during file reading: {e}")
        return

    # Final Reporting: Summarize findings 
    print("-" * 50)
    print("[*] Scan Complete. Summary of potential incidents:")
    
    # Filter the dictionary to show only IPs that met or exceeded the threshold
    potential_incidents = {ip: count for ip, count in failure_counts.items() 
                           if count >= BRUTE_FORCE_THRESHOLD}
    
    if potential_incidents:
        print(f"[!] {len(potential_incidents)} potential brute-force sources identified:")
        for ip, count in potential_incidents.items():
            print(f"    -> IP: {ip} | Failed Attempts: {count}")
    else:
        print(f"[*] No IP addresses crossed the brute-force threshold of {BRUTE_FORCE_THRESHOLD}.")
        
    print("-" * 50)


if __name__ == "__main__":
    
    print("\n--- Blue Team Log Analyzer ---")
    
    # User-Friendly Input: Prompt the user for the file path
    file_path_from_user = input("Enter the full path to the access.log file: ")
    
    analyze_logs(file_path_from_user)
