#Network Sniffer Logger

This project is a network sniffer that monitors HTTP requests (including GET and POST requests) and sends the detected information to a Discord webhook. It is designed for educational and penetration testing purposes only.
Warning

This tool should be used only for legal and ethical purposes. Unauthorized network traffic monitoring is illegal and can lead to severe legal consequences. Ensure you have explicit permission from the network owner before using this tool.
Table of Contents

    Introduction
    Features
    Installation
    Usage
    How It Works
    Potential Consequences of Malicious Use
    License

Introduction

The Network Sniffer Logger is a Python-based tool that captures and logs network traffic, specifically HTTP requests. It detects popular HTTP methods and attempts to extract potential credentials from POST requests. The logged information is sent to a specified Discord webhook for real-time monitoring.
Features

    Captures HTTP GET, POST, and other popular HTTP methods.
    Extracts and logs potential credentials from POST requests.
    Sends detected information to a Discord webhook.
    Runs in the background for a specified duration.
    Logs the IP address of the machine where the tool is running.

Installation

    Clone the repository:

    sh

git clone https://github.com/yunus-EmreX/loggerX.git
cd network-sniffer-logger

Install required Python libraries:

sh

    pip install scapy requests psutil

    Edit the script:
        Open network_sniffer.py and replace YOUR_DISCORD_WEBHOOK_URL with your actual Discord webhook URL.
        Adjust BACKGROUND_DURATION to set how long the sniffer should run in the background (in seconds).

Usage

Run the script with root privileges:

sh

sudo python3 network_sniffer.py

The script will start monitoring network traffic and send logs to the specified Discord webhook.
How It Works

    Initialization:
        The script imports necessary libraries and defines configuration variables.
        The Discord webhook URL and background duration are set.

    Packet Processing:
        The process_packet function inspects each packet to determine if it contains HTTP requests.
        If an HTTP request is detected, it extracts the method, host, and path.
        If a POST request is detected, it checks for potential credentials in the payload.

    Sending Logs:
        Detected information is sent to the Discord webhook with the machine's IP address prefixed by "logger by".

    Background Execution:
        The sniffer runs in a separate thread, allowing it to continue running even if the main application is stopped.

Potential Consequences of Malicious Use

Using this tool for unauthorized network monitoring can have serious legal and ethical consequences:

    Legal Action: Unauthorized network monitoring is illegal in many jurisdictions and can result in criminal charges, fines, and imprisonment.
    Damage to Reputation: Engaging in unethical hacking practices can severely damage your personal and professional reputation.
    Financial Consequences: Legal action and potential lawsuits can lead to significant financial penalties.
    Employment Consequences: Engaging in illegal activities can lead to job loss and difficulty finding future employment in the tech industry.

Always ensure you have explicit permission from the network owner before using this tool.
License

This project is licensed under the MIT License. See the LICENSE file for details.
