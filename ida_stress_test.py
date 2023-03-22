import os
import sys
import getpass
import re
import random
import time
import threading
from pathlib import Path
from pyad import aduser, adgroup, pyad
from pyad.adsearch import ADSearch
from pyad.adcontainer import ADContainer
from pyad.pyadexceptions import InvalidCredentials
from pypsrp.client import Client
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
from wmi import WMI


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def get_highest_user_number(existing_users):
    highest_user_number = 0
    for user in existing_users:
        match = re.match(r'user(\d+)', user)
        if match:
            user_number = int(match.group(1))
            if user_number > highest_user_number:
                highest_user_number = user_number
    return highest_user_number

def create_users(number_of_users, domain_name, domain_path, password, highest_user_number, target_ou):
    for i in range(highest_user_number + 1, highest_user_number + number_of_users + 1):
        username = f"user{i}"
        user_principal_name = f"{username}@{domain_name}"
        home_directory = f"\\\\{domain_name}\\users\\home\\{username}"
        profile_path = f"\\\\{domain_name}\\users\\profiles\\{username}"
        try:
            user = aduser.ADUser.create(username, target_ou, password=password, user_principal_name=user_principal_name, enable=True, password_never_expires=True, must_change_password=False, cannot_change_password=True, home_drive="H", home_directory=home_directory, profile_path=profile_path)
            stress_test_admins = adgroup.ADGroup.from_dn("CN=StressTestAdmins,OU=Stress Test," + domain_path)
            stress_test_admins.add_members(user)
            remote_desktop_users = adgroup.ADGroup.from_cn("Remote Desktop Users")
            remote_desktop_users.add_members(user)
            print(f"Username: {username}")
            print(f"UPN: {user_principal_name}")
            print(f"Password: {password}")
        except Exception as e:
            print(f"Error creating user {username}: {e}")


def generate_logon_events(domain_name, existing_users, password):
    def worker(username):
        time.sleep(random.randint(1, 5))
        user_principal_name = f"{username}@{domain_name}"
        try:
            with WSMan("localhost", ssl=False, auth="ntlm", encryption=False) as conn:
                with RunspacePool(conn) as pool:
                    ps = PowerShell(pool)
                    ps.add_script(r"param($User, $Password) Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock { Test-Path -Path \\$env:COMPUTERNAME\c$ -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList @($User, (ConvertTo-SecureString $Password -AsPlainText -Force)))}")
                    ps.add_parameter("User", user_principal_name)
                    ps.add_parameter("Password", password)
                    output = ps.invoke()
        except Exception as e:
            print(f"Error generating logon event for user {username}: {e}")

    threads = []
    for username in existing_users:
        thread = threading.Thread(target=worker, args=(username,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def main():
    if not is_admin():
        print("Please run this script with administrative privileges.")
        sys.exit(1)

    domain_name = input("Enter your domain name (e.g., example.local): ").strip()
    domain_path = ",".join([f"DC={part}" for part in domain_name.split(".")])
    target_ou = ADContainer.from_dn(f"OU=Stress Test,{domain_path}")

    number_of_users = int(input("Enter the number of users to create: ").strip())
    password = getpass.getpass("Enter a password for the new users: ")

    search = ADSearch()
    search.set_filter(f"(&(objectCategory=person)(objectClass=user)(memberOf=CN=StressTestAdmins,OU=Stress Test,{domain_path}))")
    search.set_attributes(["sAMAccountName"])
    existing_users = [entry["attributes"]["sAMAccountName"] for entry in search.execute_query()]

    highest_user_number = get_highest_user_number(existing_users)

    create_users(number_of_users, domain_name, domain_path, password, highest_user_number, target_ou)
    generate_logon_events(domain_name, existing_users, password)


if __name__ == "__main__":
    main()


