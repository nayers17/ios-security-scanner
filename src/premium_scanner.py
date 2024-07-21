import nmap
import json
import time
import logging

logging.basicConfig(filename='premium_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_all_ports(target):
    nm = nmap.PortScanner()
    logging.info(f"Starting scan on target: {target}")
    nm.scan(target, arguments='-p- -sV')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    service = nm[host][proto][port]['name']
                    product = nm[host][proto][port].get('product', 'unknown')
                    version = nm[host][proto][port].get('version', 'unknown')
                    open_ports.append({"port": port, "service": service, "product": product, "version": version})
    logging.info(f"Completed scan on target: {target}")
    return open_ports

def scan_vulnerabilities(open_ports):
    # Placeholder function for vulnerability scanning
    # You can integrate actual vulnerability scanning logic here
    vulnerabilities = [{"port": port['port'], "vulnerability": "Sample Vulnerability"} for port in open_ports]
    return vulnerabilities

def generate_report(vulnerabilities, target):
    report = {
        "target": target,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "vulnerabilities": vulnerabilities
    }
    with open('premium_report.json', 'w') as f:
        json.dump(report, f, indent=4)
    with open('premium_report.csv', 'w', newline='') as csvfile:
        fieldnames = ['port', 'vulnerability']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for vuln in vulnerabilities:
            writer.writerow(vuln)
    logging.info("Generated premium_report.json and premium_report.csv with scan results")

def run_scan(target):
    logging.info(f"Initiating scan on target: {target}")
    print(f"Scanning {target} for vulnerabilities...")
    open_ports = scan_all_ports(target)
    vulnerabilities = [{"port": port["port"], "vulnerability": f"Port {port['port']} ({port['service']}, {port['product']}, {port['version']}) is open"} for port in open_ports]
    
    # Integrate additional vulnerability scanning logic
    extra_vulnerabilities = scan_vulnerabilities(open_ports)
    vulnerabilities.extend(extra_vulnerabilities)
    
    generate_report(vulnerabilities, target)
    logging.info(f"Scan completed on target: {target}")
    return vulnerabilities

if __name__ == "__main__":
    target = input("Enter the target IP address: ")
    run_scan(target)
