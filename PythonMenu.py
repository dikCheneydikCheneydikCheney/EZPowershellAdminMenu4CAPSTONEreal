#!/usr/bin/env python3

#Sysadmin tasks made for Linux systems

import os
import hashlib
import subprocess
import platform
import sys
import re

def display_menu():
    """
    Displays the main menu with numbered options.
    """
    print("\n########################################################")
    print("--- Python Menu ---")
    print("1) File Hashes")
    print("2) Get, Kill, Start Processes")
    print("3) Account Creation, Removal, Information")
    print("4) Show Network Connections")
    print("5) CPU, Memory, Disk Information")
    print("0) Exit")  # Added option to exit
    print("---------------------")

def get_file_hashes():
    """
    Function to calculate file hashes with a submenu for algorithm selection.
    """
    print("\n--- File Hash Menu ---")
    print("1) MD5")
    print("2) SHA1")
    print("3) SHA256")
    print("4) SHA512")
    print("0) Back to Main Menu")
    print("----------------------")

    while True:
        choice = input("Enter your choice: ")
        if choice == "0":
            return  # Return to the main menu
        elif choice in ("1", "2", "3", "4"):
            break  # Exit the loop if a valid algorithm is chosen
        else:
            print("Invalid choice. Please try again.")

    file_path = input("Enter the path to the file: ")
    if not os.path.exists(file_path):
        print("Error: File not found.")
        input("Press Enter to return to the File Hash Menu...")
        return

    try:
        with open(file_path, "rb") as file:
            data = file.read()  # Read the file in binary mode
    except Exception as e:
        print(f"Error reading file: {e}")
        input("Press Enter to return to the File Hash Menu...")
        return

    if choice == "1":
        algorithm = "MD5"
        hasher = hashlib.md5()
    elif choice == "2":
        algorithm = "SHA1"
        hasher = hashlib.sha1()
    elif choice == "3":
        algorithm = "SHA256"
        hasher = hashlib.sha256()
    elif choice == "4":
        algorithm = "SHA512"
        hasher = hashlib.sha512()
    
    hasher.update(data)
    file_hash = hasher.hexdigest()
    print(f"{algorithm} Hash of {file_path}: {file_hash}")
    input("Press Enter to return to the File Hash Menu...")

def manage_processes():
    """
    Function to get, kill, and start processes.
    """
    while True:
        print("\n--- Process Management Menu ---")
        print("1) Get All Processes")
        print("2) Kill Process by PID")
        print("3) Start Process")
        print("0) Back to Main Menu")
        print("-------------------------------")

        choice = input("Enter your choice: ")
        if choice == "0":
            return  # Return to the main menu
        elif choice == "1":
            get_all_processes()
        elif choice == "2":
            kill_process_by_pid()
        elif choice == "3":
            start_process()
        else:
            print("Invalid choice. Please try again.")

def get_all_processes():
    """
    Gets all running processes using os and subprocess.  Linux version.
    """
    print("\n--- Running Processes ---")
    try:
        process = subprocess.Popen(['ps', '-ax', '-o', 'pid,comm,%cpu,%mem,rss'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()
        if error:
            print(f"Error: {error}")
            input("Press Enter to return to the Process Management Menu...")
            return
        lines = output.strip().split('\n')
        for line in lines[1:]:  # Skip the header line
            parts = line.split()
            if len(parts) > 4:
                pid = parts[0].strip()
                name = parts[1].strip()
                cpu_usage = parts[2].strip()
                mem_usage = parts[3].strip()
                # Convert RSS to MB
                rss_kb = int(parts[4].strip())
                mem_mb = rss_kb / 1024
                print(f"PID: {pid}, Name: {name}, CPU%: {cpu_usage}, Memory: {mem_mb:.2f} MB")
    except Exception as e:
        print(f"An error occurred: {e}")
        input("Press Enter to return to the Process Management Menu...")
        return
    input("Press Enter to return to the Process Management Menu...")

def kill_process_by_pid():
    """
    Kills a process by its PID using os.kill.  Linux version.
    """
    pid = input("Enter the PID of the process to kill: ")
    if not pid.isdigit():
        print("Invalid PID. Please enter a number.")
        input("Press Enter to return to the Process Management Menu...")
        return
    pid = int(pid)
    try:
        os.kill(pid, 9)  # 9 is SIGKILL
        print(f"Process with PID {pid} killed.")
    except OSError as e:
        print(f"Error killing process: {e}")
        input("Press Enter to return to the Process Management Menu...")

def start_process():
    """
    Starts a new process using subprocess.
    """
    process_name = input("Enter the name or path of the process to start: ")
    try:
        subprocess.Popen(process_name)
        print(f"Process '{process_name}' started.")
    except FileNotFoundError:
        print(f"Error: Process '{process_name}' not found.")
        input("Press Enter to return to the Process Management Menu...")
    except Exception as e:
        print(f"Error starting process: {e}")
        input("Press Enter to return to the Process Management Menu...")

def manage_accounts():
    """
    Function to manage user accounts.
    """
    while True:
        print("\n--- Account Management Menu ---")
        print("1) Create User")
        print("2) Remove User")
        print("3) List Users")  # Added option to list users
        print("0) Back to Main Menu")
        print("-------------------------------")

        choice = input("Enter your choice: ")
        if choice == "0":
            return  # Return to the main menu
        elif choice == "1":
            create_user()
        elif choice == "2":
            remove_user()
        elif choice == "3":  # Call the new function
            list_users()
        else:
            print("Invalid choice. Please try again.")

def create_user():
    """
    Creates a new user on the system.
    """
    username = input("Enter the username for the new user: ")
    password = input("Enter the password for the new user: ")  # Consider secure input methods
    try:
        subprocess.run(['useradd', '-m', '-p', password, username], check=True)  # Don't store password in script
        print(f"User '{username}' created.")
    except subprocess.CalledProcessError as e:
        print(f"Error creating user: {e}")
        input("Press Enter to return to the Account Management Menu...")

def remove_user():
    """
    Removes a user from the system.
    """
    username = input("Enter the username of the user to remove: ")
    try:
        subprocess.run(['userdel', '-r', username], check=True)  # -r removes home directory
        print(f"User '{username}' removed.")
    except subprocess.CalledProcessError as e:
        print(f"Error removing user: {e}")
        input("Press Enter to return to the Account Management Menu...")

def list_users():
    """
    Lists all regular and sudo users on the system.
    """
    print("\n--- System Users ---")
    regular_users = []
    sudo_users = []
    try:
        # Get all users from /etc/passwd
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) > 0:
                    username = parts[0]
                    # Filter out system accounts.  A common heuristic is to check if the UID is less than 1000.
                    if int(parts[2]) >= 1000:
                        regular_users.append(username)
        # Get sudo users from /etc/group
        with open("/etc/group", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) > 0 and parts[0] == "sudo":
                    # Sudo group found, get the users
                    if len(parts) > 3:
                       users = parts[3].split(',')
                       for user in users:
                         if user in regular_users and user not in sudo_users:
                            sudo_users.append(user)
                    break # Stop looking after finding the sudo group

        print("\nRegular Users:")
        for user in regular_users:
            if user not in sudo_users:
                print(user)
        print("\nSudo Users:")
        for user in sudo_users:
            print(user)
    except Exception as e:
        print(f"Error listing users: {e}")
        input("Press Enter to return to the Account Management Menu...")
    input("Press Enter to return to the Account Management Menu...")

def show_network_connections():
    """
    Displays current network connections using the 'ss' command (Linux).
    """
    print("\n--- Current Network Connections ---")
    try:
        process = subprocess.Popen(['ss', '-tulpn'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()
        if error:
            print(f"Error: {error}")
        else:
            print(output)  # Print the output of the 'ss' command
    except Exception as e:
        print(f"An error occurred: {e}")
    input("Press Enter to return to the Network Management Menu...")

def get_system_info():
    """
    Function to get CPU, memory, and disk information using built-in modules.
    """
    print("\n--- System Information ---")
    try:
        # Get CPU information
        cpu_usage = get_cpu_usage_linux()
        print(f"Platform: {platform.system()} {platform.release()} {platform.machine()}")
        print(f"Processor: {platform.processor()}") #prints the processor name

        if cpu_usage is not None:
            print(f"CPU Usage: {cpu_usage:.2f}%")
        else:
            print("Could not retrieve CPU usage.")
        print("")

        # Get memory information
        #  We can try to get total memory from the system, but it's OS-dependent and not very reliable.
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if 'MemTotal' in line:
                        mem_total_kb = int(line.split(':')[1].strip().split(' ')[0])
                        mem_total_gb = mem_total_kb / (1024 ** 2)  # Convert KB to GB
                        print(f"Total Memory: {mem_total_gb:.2f} GB")
                        break
        except Exception:
            print("Total Memory: N/A (Could not read /proc/meminfo)")
        
        memory_usage = get_memory_usage_linux()
        if memory_usage is not None:
            print(f"Memory Usage: {memory_usage:.2f}%")
        else:
            print("Could not retrieve memory usage.")
        print("")

        # Get disk information (limited with built-in modules)
        #  We can get free space, but not total or used space, in a cross-platform way.
        try:
            free_bytes = os.statvfs('/').f_bavail * os.statvfs('/').f_frsize
            total_bytes = os.statvfs('/').f_blocks * os.statvfs('/').f_frsize
            free_gb = free_bytes / (1024 ** 3)
            total_gb = total_bytes / (1024 ** 3)
            used_gb = total_gb - free_gb
            print(f"Total Disk Space: {total_gb:.2f} GB")
            print(f"Free Disk Space: {free_gb:.2f} GB")
            print(f"Used Disk Space: {used_gb:.2f} GB")
        except Exception as e:
            print(f"Error getting disk information: {e}")
            print("Disk Space: N/A (Not fully available with built-in modules)")
    except Exception as e:
        print(f"An error occurred: {e}")
    input("Press Enter to return to the main menu...")

def get_cpu_usage_linux():
    """Gets the CPU usage percentage on Linux."""
    try:
        # Use subprocess.run for better error handling and security
        result = subprocess.run(
            ["top", "-bn1"], capture_output=True, text=True, check=True
        )
        output = result.stdout

        # Extract the CPU usage using a regular expression
        cpu_line = next((line for line in output.splitlines() if "Cpu(s)" in line), None) #changed this line

        if cpu_line: #added this if statement
            match = re.search(r"(\d+\.\d+)%* id", cpu_line)  # More robust regex
            if match:
                idle_percentage = float(match.group(1))
                cpu_usage = 100 - idle_percentage
                return cpu_usage
            else:
                print("Error: Could not parse CPU usage from top output.")
                return None  # Explicitly return None on failure
        else:
            print("Error: Could not find Cpu(s) line in top output")
            return None

    except subprocess.CalledProcessError as e:
        print(f"Error running top: {e}")
        print(f"Command: {e.cmd}")  # Print the command that failed
        print(f"Stderr:\n{e.stderr}")  # Print the error output
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def get_memory_usage_linux():
    """Gets the memory usage percentage on Linux."""
    try:
        result = subprocess.run(["free"], capture_output=True, text=True, check=True)
        output = result.stdout
        mem_line = next(line for line in output.splitlines() if "Mem:" in line)
        parts = mem_line.split()
        total_memory = int(parts[1])
        used_memory = int(parts[2])
        if total_memory == 0:
            return 0.0
        memory_usage = (used_memory / total_memory) * 100.0
        return memory_usage
    except subprocess.CalledProcessError as e:
        print(f"Error running free: {e}")
        print(f"Command: {e.cmd}")
        print(f"Stderr:\n{e.stderr}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def main():
    """
    Main function to run the menu loop.
    """
    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            get_file_hashes()
        elif choice == "2":
            manage_processes()
        elif choice == "3":
            manage_accounts()
        elif choice == "4":
            show_network_connections()
        elif choice == "5":
            get_system_info()
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")  # Pause

if __name__ == "__main__":
    main()
