import nmap
import json
import time

def scan_all_ports(target):
    nm = nmap.PortScanner()
    print(f"Starting scan on target: {target}")
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
    print(f"Completed scan on target: {target}")
    return open_ports

def run_scan(target):
    print(f"Scanning {target} for vulnerabilities...")
    open_ports = scan_all_ports(target)
    vulnerabilities = [{"port": port["port"], "vulnerability": f"Port {port['port']} ({port['service']}, {port['product']}, {port['version']}) is open"} for port in open_ports]
    report = {
        "target": target,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "vulnerabilities": vulnerabilities
    }
    with open('report.json', 'w') as f:
        json.dump(report, f, indent=4)
    print(f"Found vulnerabilities: {vulnerabilities}")
    print("Report saved to report.json")

if __name__ == "__main__":
    target = input("Enter the target IP address: ")
    run_scan(target)
