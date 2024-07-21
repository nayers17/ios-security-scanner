import socket

def run_scan(target):
    """
    Scans the target IP address for vulnerabilities.

    Parameters:
    target (str): The IP address of the target device.

    Returns:
    list: A list of found vulnerabilities.
    """
    print(f"Scanning {target} for vulnerabilities...")
    vulnerabilities = []
    ports = [80, 443, 22, 21]
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((target, port))
        if result == 0:
            vulnerabilities.append(f"Port {port} is open")
        sock.close()
    return vulnerabilities

if __name__ == "__main__":
    target = input("Enter the target IP address: ")
    vulnerabilities = run_scan(target)
    print(f"Found vulnerabilities: {vulnerabilities}")

