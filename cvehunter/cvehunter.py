#!/usr/bin/env python3
import argparse
import socket
import requests
import sys
import time
import json
import csv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Initialize Rich Console
console = Console()

# Define text styles
bold = "[bold]"
red = "[red]"
cyan = "[cyan]"
yellow = "[yellow]"
magenta = "[magenta]"
green = "[green]"
white = "[white]"
reset = "[reset]"

# Function to display a fancy banner
def banner(output_file=None):
    banner_text = f"""{bold}{red}
 ▄████▄ ██▒   █▓▓█████  ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓▓█████  ██▀███  
▒██▀ ▀█▓██░   █▒▓█   ▀ ▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄▓██  █▒░▒███   ▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒▒██ █░░▒▓█  ▄ ░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
▒ ▓███▀ ░ ▒▀█░  ░▒████▒░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░ ░ ▐░  ░░ ▒░ ░ ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒    ░ ░░   ░ ░  ░ ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░
░           ░░     ░    ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░         ░     ░░   ░ 
░ ░          ░     ░  ░ ░  ░  ░   ░              ░             ░  ░   ░     
░           ░                                                               
                              {bold}{white} github:- @Shubhamrooter | Version: 1.0.0{reset}\n"""
    panel = Panel.fit(
        banner_text,
        title="[bold blue]Welcome to CVE Hunter[/bold blue]",
        border_style="bold magenta"
    )
    if output_file:
        # Use a separate console instance for file output
        file_console = Console(file=output_file)
        file_console.print(panel)
    else:
        console.print(panel)  # Print to the console

# Function to resolve a domain to an IP address
def resolve_domain(domain):
    console.print(f"{cyan}[+] Resolving domain: {domain}{reset}")
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"{green}[+] Resolved {domain} to {ip}{reset}")
        return ip
    except socket.gaierror:
        console.print(f"{yellow}[!] Unable to resolve domain: {domain}{reset}")
        return None

# Function to log unresolvable domains
def log_unresolvable_domains(domains, log_file="unresolvable_domains.txt"):
    with open(log_file, "w") as f:
        for domain in domains:
            f.write(f"{domain}\n")
    console.print(f"{green}[+] Logged unresolvable domains to {log_file}{reset}")

# Function to validate and resolve targets
def validate_and_resolve_targets(targets):
    valid_targets = []
    unresolvable_domains = []
    for target in targets:
        if target.replace(".", "").isdigit():  # Check if it's an IP address
            valid_targets.append(target)
        else:  # Resolve domain to IP
            ip = resolve_domain(target)
            if ip:
                valid_targets.append(ip)
            else:
                unresolvable_domains.append(target)
    if unresolvable_domains:
        log_unresolvable_domains(unresolvable_domains)
    return valid_targets

# Function to fetch data from the API with rate limiting
def fetch_data(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    console.print(f"{cyan}[+] Fetching data for IP: {ip}...{reset}")
    try:
        response = requests.get(url)
        console.print(f"{green}[+] API Response: {response.status_code}{reset}")
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            console.print(f"{yellow}[!] No data found for IP: {ip}{reset}")
            return None
        elif response.status_code == 429:  # Rate limit exceeded
            console.print(f"{yellow}[!] Rate limit exceeded. Waiting for 10 seconds...{reset}")
            time.sleep(10)
            return fetch_data(ip)  # Retry
        else:
            console.print(f"{red}[!] Error fetching data: {response.status_code}{reset}")
            return None
    except requests.RequestException as e:
        console.print(f"{red}[!] Request failed: {e}{reset}")
        return None

# Function to fetch CVE details (base score, severity, description)
def get_cve_details(cve_id):
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return "Error fetching data", "N/A", "N/A", url
        
        soup = BeautifulSoup(response.text, 'html.parser')
        base_score_section = soup.find('a', {'data-testid': 'vuln-cvss3-panel-score'})
        severity_section = soup.find('span', {'data-testid': 'vuln-cvss3-panel-severity'})
        description_section = soup.find('p', {'data-testid': 'vuln-description'})
        
        base_score = base_score_section.text.strip() if base_score_section else "N/A"
        severity = severity_section.text.strip() if severity_section else "N/A"
        description = description_section.text.strip() if description_section else "N/A"
        
        return base_score, severity, description, url
    except Exception as e:
        return f"Error fetching details: {str(e)}", "N/A", "N/A", url

# Function to check exploit availability for a CVE
def check_exploit_availability(cve_id):
    url = f"https://www.exploit-db.com/search?cve={cve_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            exploit_count = len(soup.find_all('tr', {'class': 'exploit_row'}))
            return f"{exploit_count} exploit(s) found" if exploit_count > 0 else "No exploits found"
        else:
            return "Error checking exploit database"
    except Exception as e:
        return f"Error: {str(e)}"

# Function to display CVEs in a Rich table
def display_cves(cves, output_file=None):
    table = Table(title=f"{green}Vulnerabilities (CVEs){reset}", show_lines=True)
    table.add_column("CVE ID", style="cyan")
    table.add_column("Base Score", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Description", style="yellow")
    table.add_column("Exploit Status", style="blue")
    
    if not cves:
        console.print("N/A")
        return
    
    with ThreadPoolExecutor() as executor:
        details_results = executor.map(get_cve_details, cves)
        exploit_results = executor.map(check_exploit_availability, cves)
    
    for cve, (base_score, severity, description, _), exploit_status in zip(cves, details_results, exploit_results):
        table.add_row(cve, base_score, severity, description, exploit_status)
    
    if output_file:
        file_console = Console(file=output_file)
        file_console.print(table)
    else:
        console.print(table)

# Function to display hostnames
def display_hostnames(hostnames, output_file=None):
    output = f"\n{green}Hostnames:{reset}\n"
    if hostnames:
        for hostname in hostnames:
            output += f" -> {hostname}\n"
    else:
        output += "N/A\n"
    
    if output_file:
        output_file.write(output)
    else:
        console.print(output)

# Function to display ports
def display_ports(ports, output_file=None):
    output = f"\n{green}Open Ports:{reset}\n"
    if ports:
        for port in ports:
            output += f" -> {port}\n"
    else:
        output += "N/A\n"
    
    if output_file:
        output_file.write(output)
    else:
        console.print(output)

# Function to export results in JSON or CSV format
def export_results(data, format="json", output_file="results.json"):
    if format == "json":
        with open(output_file, "w") as f:
            json.dump(data, f, indent=4)
    elif format == "csv":
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["CVE ID", "Base Score", "Severity", "Description", "Exploit Status"])
            for cve, details in data.items():
                writer.writerow([cve, *details])
    console.print(f"{green}[+] Results exported to {output_file}{reset}")

# Function to scan multiple targets in bulk
def scan_bulk_targets(targets):
    results = {}
    with ThreadPoolExecutor() as executor:
        for target in targets:
            result = executor.submit(fetch_data, target).result()
            if result:  # Only store valid results
                results[target] = result
    return results

# Interactive mode for user input
def interactive_mode():
    console.print(f"{cyan}[+] Interactive Mode{reset}")
    target = console.input(f"{yellow}Enter domain/IP: {reset}")
    data = fetch_data(target)
    if data:
        display_hostnames(data.get("hostnames", []))
        display_ports(data.get("ports", []))
        display_cves(data.get("vulns", []))

# Main function
def main():
    banner()  # Display the banner first
    parser = argparse.ArgumentParser(description="Ultimate CVE Hunter Tool")
    parser.add_argument("-d", "--domain", help="IP address or domain to scan")
    parser.add_argument("-f", "--file", help="File containing list of domains/IPs to scan")
    parser.add_argument("-o", "--output", help="Output file to store the results (e.g., result.txt)", type=str)
    parser.add_argument("--export", help="Export results in JSON/CSV format", choices=["json", "csv"])
    parser.add_argument("--interactive", help="Run in interactive mode", action="store_true")
    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
        return

    if args.output:
        output_file = open(args.output, "w", encoding="utf-8")
        banner(output_file)
    else:
        output_file = None

    if args.file:
        with open(args.file, "r") as f:
            targets = [line.strip() for line in f.readlines()]
        valid_targets = validate_and_resolve_targets(targets)
        results = scan_bulk_targets(valid_targets)
        for target, result in results.items():
            console.print(f"{cyan}[+] Results for {target}:{reset}")
            display_cves(result.get("vulns", []))
    else:
        if not args.domain:
            input_data = sys.stdin.read().strip()  # Read the piped input
            if not input_data:
                console.print(f"{red}[!] No input provided via pipe or argument.{reset}")
                exit(1)
            target = input_data
        else:
            target = args.domain

        if not target.replace(".", "").isdigit():
            console.print(f"{yellow}[+] Resolving domain {target} to IP...{reset}")
            target = resolve_domain(target)
            if not target:
                exit(1)
            console.print(f"{green}[+] Resolved IP: {target}{reset}")

        console.print(f"{cyan}[+] Fetching data for IP: {target}...{reset}")
        data = fetch_data(target)
        if data:
            display_hostnames(data.get("hostnames", []), output_file)
            display_ports(data.get("ports", []), output_file)
            display_cves(data.get("vulns", []), output_file)

        if args.export:
            export_results(data, format=args.export, output_file=f"results.{args.export}")

    if output_file:
        output_file.close()

if __name__ == "__main__":
    main()
