from scanner import run_scan

target_ip = "192.168.1.1"
vulnerabilities = run_scan(target_ip)
print(f"Found vulnerabilities: {vulnerabilities}")
