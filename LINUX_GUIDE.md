# User Guide: Comprehensive Network Security Scan with IoT Security Scanner (Linux)

## Step 1: Understanding Your Network

1. **Identify Your Network Range**:
    - Open your terminal.
    - Type the command `ip addr show` and press Enter.
    - Look for a line similar to `inet 192.168.4.xxx/24`. This tells you your network range. For example, if you see `192.168.4.175/24`, your network range is `192.168.4.0/24`.

2. **Note Your Network Range**:
    - Your network range will typically be in the format `192.168.x.0/24`, where `x` can be any number between 0 and 255. This range includes all devices connected to your network.

## Step 2: Setting Up the IoT Security Scanner

1. **Download and Install the IoT Security Scanner**:
    - Ensure you have Python installed on your computer.
    - Clone the IoT Security Scanner repository from GitHub:
    ```bash
    git clone git@github.com:nayers17/iot-security-scanner.git
    ```
    - Navigate to the installation directory:
    ```bash
    cd ~/iot-security-scanner
    ```

## Step 3: Performing a Basic Scan

1. **Free Version (Basic Scan)**:
    - This scan will check for open ports on a specific device.
    - In your terminal, navigate to the `free` directory:
    ```bash
    cd free
    ```
    - Run the scanner with the command:
    ```bash
    python3 scanner.py
    ```
    - Enter the target IP address of the device you want to scan when prompted.

## Step 4: Performing an Advanced Scan

1. **Premium Version (Detailed Scan)**:
    - This scan checks for open ports and additional vulnerabilities.
    - Navigate to the `src` directory:
    ```bash
    cd ../src
    ```
    - Run the premium scanner:
    ```bash
    python3 premium_scanner.py
    ```
    - Enter the target IP address of the device you want to scan when prompted.

2. **Advanced Premium Version (Network-Wide Scan)**:
    - This version includes real-time monitoring and a graphical user interface (GUI).
    - Navigate to the `src` directory:
    ```bash
    cd ../src
    ```
    - Run the advanced premium GUI:
    ```bash
    python3 advanced_premium_gui.py
    ```
    - Enter your network range in the format `192.168.x.0/24` in the Network Address field.
    - Click "Run Network Scan" to scan all devices on your network.

## Step 5: Understanding Scan Results

1. **Interpreting the Results**:
    - **Open Ports**: The scanner will display a list of open ports on the scanned devices.
    - **Protocols**: Each open port will have a corresponding protocol (e.g., HTTP, FTP).
    - **Applications**: The scanner will also attempt to identify which applications are using the open ports.

2. **Threat Levels**:
    - The scanner provides a threat level for each open port based on the application and protocol.
    - High-risk ports should be addressed immediately to protect your network.

## Step 6: Taking Action

1. **Closing Vulnerable Ports**:
    - The scanner will ask if you want to close open ports. Choose "Yes" to close all or select specific ports.
    - Follow the on-screen instructions to close ports.

2. **Real-Time Monitoring**:
    - The advanced premium version offers real-time monitoring. Enable this feature to continuously monitor your network for new threats.

3. **Email Notifications**:
    - Set up email notifications to receive alerts about new vulnerabilities. Follow the prompts in the advanced premium GUI to configure this feature.
