import requests
import json
import sys
import os
import csv
import ipaddress  # For IP validation
import time       # For implementing delays

def is_valid_ip(ip):
    """Validate an IPv4 or IPv6 address using the ipaddress module."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_geolocation(ip):
    """Fetch geolocation data for a given IP address using ip-api.com."""
    url = f"https://freeipapi.com/api/json/{ip}"  # Switched to HTTPS for security
    try:
        print(f"Fetching geolocation for IP: {ip}...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        
        if data.get('status') == 'fail':
            print(f"Failed to retrieve data for IP {ip}: {data.get('message')}")
            return None
        
        return data
    except requests.exceptions.Timeout:
        print(f"Request timed out for IP {ip}.")
        return None
    except requests.exceptions.ConnectionError:
        print(f"Connection error occurred while fetching data for IP {ip}.")
        return None
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred for IP {ip}: {http_err}")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON response for IP {ip}.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred for IP {ip}: {e}")
        return None

def save_results(results, file_path, format):
    """Save geolocation results to a file in JSON or CSV format."""
    try:
        if format.lower() == 'json':
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4)
            print(f"Results successfully saved to {file_path} in JSON format.")
        elif format.lower() == 'csv':
            if not results:
                print("No data to save.")
                return
            # Determine the CSV headers from the keys of the first result
            headers = results[0].keys()
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(results)
            print(f"Results successfully saved to {file_path} in CSV format.")
        else:
            print("Unsupported file format. Please choose either 'json' or 'csv'.")
    except Exception as e:
        print(f"An error occurred while saving the file: {e}")

def process_single_ip():
    ip = input("Please enter the IP address: ").strip()
    if not ip:
        print("No IP address entered.")
        return
    
    if not is_valid_ip(ip):
        print("Invalid IP address format.")
        return

    data = get_geolocation(ip)
    if data:
        print(json.dumps(data, indent=4))
        save_option = input("Would you like to save the result to a file? (y/n): ").strip().lower()
        if save_option == 'y':
            save_format = input("Choose the file format (json/csv): ").strip().lower()
            file_path = input("Enter the full path for the output file (including extension): ").strip()
            save_results([data], file_path, save_format)

def process_file(file_path):
    if not os.path.isfile(file_path):
        print(f"The file '{file_path}' does not exist.")
        return

    try:
        with open(file_path, 'r') as file:
            ips = [line.strip() for line in file if line.strip()]
        
        if not ips:
            print("The file is empty or contains only whitespace.")
            return

        results = []
        for idx, ip in enumerate(ips, start=1):
            if not is_valid_ip(ip):
                print(f"Skipping invalid IP address format: {ip}")
                continue
            print(f"Geolocation for IP {ip}:")
            data = get_geolocation(ip)
            if data:
                print(json.dumps(data, indent=4))
                results.append(data)
            print('-' * 40)
            
            # Implement a 3-second delay between requests, except after the last IP
            if idx < len(ips):
                print("Waiting for 3 seconds to respect rate limits...")
                time.sleep(3)
        
        if results:
            save_option = input("Would you like to save the results to a file? (y/n): ").strip().lower()
            if save_option == 'y':
                save_format = input("Choose the file format (json/csv): ").strip().lower()
                output_file = input("Enter the full path for the output file (including extension): ").strip()
                save_results(results, output_file, save_format)
    except Exception as e:
        print(f"An error occurred while processing the file: {e}")

def main():
    print("IP Geolocation Tool")
    print("1. Enter a single IP address")
    print("2. Provide a text file with IP addresses")
    choice = input("Please select an option (1 or 2): ").strip()

    if choice == '1':
        process_single_ip()
    elif choice == '2':
        file_path = input("Please enter the path to the text file: ").strip()
        process_file(file_path)
    else:
        print("Invalid option selected. Please choose either 1 or 2.")
        sys.exit(1)

if __name__ == "__main__":
    main()
