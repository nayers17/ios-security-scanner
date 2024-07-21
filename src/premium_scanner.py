import nmap
import json
import time
import logging

logging.basicConfig(filename='premium_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_all_ports(target):
    nm = nmap.PortScanner()
    logging.info(f"Starting scan on target: {target}")
    nm.scan(target, arguments='-p-')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
    logging.info(f"Completed scan on target: {target}")
    return open_ports

def generate_report(vulnerabilities):
    report = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "vulnerabilities": vulnerabilities
    }
    with open('premium_report.json', 'w') as f:
        json.dump(report, f, indent=4)
    logging.info("Generated premium_report.json with scan results")

def run_scan(target):
    logging.info(f"Initiating scan on target: {target}")
    print(f"Scanning {target} for vulnerabilities...")
    open_ports = scan_all_ports(target)
    vulnerabilities = [{"port": port, "vulnerability": f"Port {port} is open"} for port in open_ports]
    generate_report(vulnerabilities)
    logging.info(f"Scan completed on target: {target}")
    return vulnerabilities

if __name__ == "__main__":
    target = input("Enter the target IP address: ")
    vulnerabilities = run_scan(target)
    print(f"Found vulnerabilities: {vulnerabilities}")
