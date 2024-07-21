import nmap
import json
import time
import logging
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import csv
from flask import Flask, jsonify, request, render_template

logging.basicConfig(filename='advanced_premium_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

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

def send_email_report(report_path, recipient_email):
    sender_email = "your-email@example.com"
    password = "your-email-password"

    message = MIMEMultipart("alternative")
    message["Subject"] = "Advanced Premium Scan Report"
    message["From"] = sender_email
    message["To"] = recipient_email

    with open(report_path, 'r') as f:
        report_content = f.read()

    part1 = MIMEText(report_content, "plain")
    part2 = MIMEText(report_content, "html")

    message.attach(part1)
    message.attach(part2)

    with smtplib.SMTP_SSL("smtp.example.com", 465) as server:
        server.login(sender_email, password)
        server.sendmail(
            sender_email, recipient_email, message.as_string()
        )

def real_time_monitor(target):
    while True:
        logging.info(f"Real-time monitoring of target: {target}")
        vulnerabilities = run_scan(target)
        if vulnerabilities:
            logging.warning(f"Detected vulnerabilities in real-time monitoring: {vulnerabilities}")
            send_email_report('premium_report.json', 'recipient@example.com')
        time.sleep(3600)  # Run the scan every hour

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    vulnerabilities = run_scan(target)
    return jsonify(vulnerabilities)

if __name__ == "__main__":
    # Run real-time monitor in a separate thread
    target = "192.168.1.1"  # Example target for real-time monitoring
    monitoring_thread = threading.Thread(target=real_time_monitor, args=(target,))
    monitoring_thread.start()

    # Start the Flask web server
    app.run(host='0.0.0.0', port=5000)
