# User Guide: Comprehensive Network Security Scan with IoT Security Scanner (Windows)

## Step 1: Understanding Your Network

1. **Identify Your Network Range**:
    - Open the Command Prompt.
    - Type the command `ipconfig` and press Enter.
    - Look for a line under your network adapter that starts with `IPv4 Address`. This is your IP address. Note the range, which typically looks like `192.168.x.x`.

2. **Note Your Network Range**:
    - Your network range will typically be in the format `192.168.x.0/24`, where `x` can be any number between 0 and 255. This range includes all devices connected to your network.

## Step 2: Setting Up the IoT Security Scanner

1. **Download and Install Python**:
    - Download Python from [python.org](https://www.python.org/downloads/).
    - Install Python by running the downloaded installer and following the on-screen instructions. Make sure to check the box that says "Add Python to PATH".

2. **Download and Install the IoT Security Scanner**:
    - Download the IoT Security Scanner tool from the provided link or repository.
    - Extract the downloaded files to a known location on your computer.

3. **Navigate to the Installation Directory**:
    - Open the Command Prompt.
    - Use the `cd` command to navigate to the directory where you extracted the IoT Security Scanner.
    - Example:
    ```bash
    cd C:\path\to\iot-security-scanner
    ```

## Step 3: Performing a Basic Scan

1. **Free Version (Basic Scan)**:
    - This scan will check for open ports on a specific device.
    - In the Command Prompt, navigate to the `free` directory:
    ```bash
    cd free
    ```
    - Run the scanner with the command:
    ```bash
    python scanner.py
    ```
    - Enter the target IP address of the device you want to scan when prompted.

## Step 4: Performing an Advanced Scan

1. **Premium Version (Detailed Scan)**:
    - This scan checks for open ports and additional vulnerabilities.
    - Navigate to the `src` directory:
    ```bash
    cd ..\src
    ```
    - Run the premium scanner:
    ```bash
    python premium_scanner.py
    ```
    - Enter the target IP address of the device you want to scan when prompted.

2. **Advanced Premium Version (Network-Wide Scan)**:
    - This version includes real-time monitoring and a graphical user interface (GUI).
    - Navigate to the `src` directory:
    ```bash
    cd ..\src
    ```
    - Run the advanced premium GUI:
    ```bash
    python advanced_premium_gui.py
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

