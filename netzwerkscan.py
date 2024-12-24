#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# erstellt von ELFO
import nmap
import os
import time
import subprocess
import tempfile
import argparse
import csv
import logging
from datetime import datetime
import tqdm
import networkx as nx
import matplotlib.pyplot as plt
import json
from concurrent.futures import ThreadPoolExecutor

# Set up logging
logging.basicConfig(filename='nmap_scan.log', level=logging.INFO,
                  format='%(asctime)s - %(levelname)s - %(message)s')

os.system('clear')

#Multithreading
def scan_multiple_ranges(ip_ranges, nmap_arguments):
  with ThreadPoolExecutor(max_workers=4) as executor:
      futures = [executor.submit(scan_network, ip_range, nmap_arguments) for ip_range in ip_ranges]
      results = [future.result() for future in futures]
  return results

#visuelle darstellung
def visualize_topology(devices):
  G = nx.Graph()
  for device in devices:
      G.add_node(device['ip'], label=device['hostname'])
      for port in device['open_ports']:
          G.add_edge(device['ip'], f"{device['ip']}:{port}")

  pos = nx.spring_layout(G)
  nx.draw(G, pos, with_labels=True, node_size=2000, node_color='lightblue', font_size=10, font_weight='bold')
  plt.show()

#vulnerability check
def check_vulnerabilities(devices):
  known_vulnerabilities = {
      'ftp': 'Check for anonymous login',
      'ssh': 'Check for outdated versions',
      'http': 'Check for default credentials'
  }

  for device in devices:
      for port in device['open_ports']:
          service = port.split()[2]
          if service in known_vulnerabilities:
              print(f"Potential vulnerability on {device['ip']}:{port} - {known_vulnerabilities[service]}")

#export json und html
def save_to_json(devices, filename):
  with open(filename, 'w') as jsonfile:
      json.dump(devices, jsonfile, indent=4)

def save_to_html(devices, filename):
  html_content = "<html><body><h1>Scan Results</h1><table border='1'>"
  html_content += "<tr><th>IP</th><th>MAC</th><th>Hostname</th><th>OS</th><th>Open Ports</th></tr>"
  for device in devices:
      html_content += f"<tr><td>{device['ip']}</td><td>{device['mac']}</td><td>{device['hostname']}</td><td>{device['os']}</td><td>{', '.join(device['open_ports'])}</td></tr>"
  html_content += "</table></body></html>"

  with open(filename, 'w') as htmlfile:
      htmlfile.write(html_content)



# Define terminal width and color class
WIDTH = 160  # Adjust this to your terminal width

class Color:
  CYAN = '\033[96m'
  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  RED = '\033[91m'
  RESET = '\033[0m'

# Banner
BANNER_TEXT = r"""
 ______                                     _
|  ___ \       _                           | |
| |   | | ____| |_  _____ _ _ _  ____  ____| |  _  ___  ____ ____ ____  ____   ____  ____
| |   | |/ _  )  _)(___  ) | | |/ _  )/ ___) | / )/___)/ ___) _  |  _ \|  _ \ / _  )/ ___)
| |   | ( (/ /| |__ / __/| | | ( (/ /| |   | |< (|___ ( (__( ( | | | | | | | ( (/ /| |
|_|   |_|\____)\___|_____)\____|\____)_|   |_| \_|___/ \____)_||_|_| |_|_| |_|\____)_|

 _
| |
| | _  _   _
| || \| | | |
| |_) ) |_| |
|____/ \__  |
      (____/


░▒▓████████▓▒░▒▓█▓▒░      ░▒▓████████▓▒░▒▓██████▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░
░▒▓██████▓▒░ ░▒▓█▓▒░      ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░
░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░      ░▒▓██████▓▒░





"""

def print_banner():
  print()
  print('*' * WIDTH)
  banner_centered = BANNER_TEXT.center(WIDTH)
  print(f"{Color.CYAN}{banner_centered}{Color.RESET}")
  print('*' * WIDTH)
  print()
  print(f"{Color.GREEN}Ein kleiner Netzwerkscanner der nmap nutzt :{Color.RESET}")
  print()
  print(f"{Color.YELLOW}Du kannst das script auch mit command-line optionen ausführen {Color.RESET}")
  print(f"{Color.YELLOW}For verbose output: sudo python3 netswerscanp.y -v {Color.RESET}")
  print(f"{Color.YELLOW}To save results to CSV_json_html: sudo python3 netswerscan.py -o results.csv {Color.RESET}")
  print(f"{Color.YELLOW}Both options: sudo python3 netswerscan.py -v -o results.csv{Color.RESET}")

  print()
  print()
  ##  Networkscan
def scan_network(ip_range, nmap_arguments, verbose=False):
  devices = []
  try:
      with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
          command = ["nmap", "-oX", tmpfile.name, ip_range] + nmap_arguments.split()
          process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

          # Fortschrittsanzeige
          for line in tqdm.tqdm(iter(process.stdout.readline, ''), desc="Scanning", unit=" hosts"):
              if verbose:
                  print(line, end='')

          process.wait()

          with open(tmpfile.name, 'r') as xml_output:
              nmap_output = xml_output.read()

      os.remove(tmpfile.name)

      nm = nmap.PortScanner()
      nm.analyse_nmap_xml_scan(nmap_output)

      for host in nm.all_hosts():
          mac = nm[host]['addresses'].get('mac', 'Unknown')
          hostname = nm[host].hostname() or "Unknown"
          open_ports = []
          os_info = nm[host].get('osmatch', [{'name': 'Unknown'}])[0]['name']

          for proto in nm[host].all_protocols():
              lport = nm[host][proto].keys()
              for port in lport:
                  service = nm[host][proto][port]['name']
                  version = nm[host][proto][port].get('version', '')
                  state = nm[host][proto][port]['state']
                  open_ports.append(f"{port}/{proto} {state} {service} {version}")

          devices.append({
              'ip': host,
              'mac': mac,
              'hostname': hostname,
              'os': os_info,
              'open_ports': open_ports
          })

      if verbose:
          print(f"{Color.YELLOW}Raw nmap output:{Color.RESET}")
          print(process.stdout)

  except subprocess.CalledProcessError as e:
      logging.error(f"Error executing nmap: {e.stderr}")
      print(f"{Color.RED}Error executing nmap: {e.stderr}{Color.RESET}")
  except Exception as e:
      logging.error(f"Error scanning or parsing nmap output: {e}")
      print(f"{Color.RED}Error scanning or parsing nmap output: {e}{Color.RESET}")
  except Exception as e:
      logging.error(f"Error scanning or parsing nmap output: {e}")
      print(f"{Color.RED}Error scanning or parsing nmap output: {e}{Color.RESET}")
  return devices

#Save to csv
def save_to_csv(devices, filename):
  with open(filename, 'w', newline='') as csvfile:
      fieldnames = ['IP', 'MAC', 'Hostname', 'OS', 'Open Ports']
      writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
      writer.writeheader()
      for device in devices:
          writer.writerow({
              'IP': device['ip'],
              'MAC': device['mac'],
              'Hostname': device['hostname'],
              'OS': device['os'],
              'Open Ports': ', '.join(device['open_ports'])
          })

def main():
  parser = argparse.ArgumentParser(description='Network Scanner using Nmap')
  parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
  parser.add_argument('-o', '--output', help='Save results to CSV file')
  args = parser.parse_args()

  while True:
      print_banner()

      ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
      default_nmap_arguments = "-sS -A -PN"

      print(f"{Color.GREEN}Some examples of nmap arguments:{Color.RESET}")
      print("""
      -T4: Sets the timing template to aggressive
      -F: Performs a fast scan (only scans 100 common ports)
      -A: Enables OS detection, version detection, script scanning, and traceroute
      -Pn: Treats all hosts as online, skipping host discovery
      -p <port ranges>: Specifies which ports to scan (e.g., -p 22,80,443)
      -sS: Performs a TCP SYN scan (stealth scan)
      --script <script name>: Runs an nmap scripting engine (NSE) script
      """)

      nmap_arguments = input(f"Enter nmap arguments (default: {default_nmap_arguments}): ")
      if not nmap_arguments:
          nmap_arguments = default_nmap_arguments

      print(f"{Color.RED}Scanning network...{Color.RESET}")
      devices = scan_network(ip_range, nmap_arguments, args.verbose)

      print(f"\n{Color.GREEN}Devices found:{Color.RESET}")
      for device in devices:
          print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}")
          print(f"OS: {device['os']}")
          print("Open Ports:")
          for port in device['open_ports']:
              print(f"  - {port}")
          print()

      if args.output:
          save_to_csv(devices, args.output)
          save_to_json(devices, args.output.replace('.csv', '.json'))
          save_to_html(devices, args.output.replace('.csv', '.html'))
          print(f"{Color.GREEN}Results saved to {args.output}, {args.output.replace('.csv', '.json')}, and {args.output.replace('.csv', '.html')}{Color.RESET}")

      visualize_topology(devices)
      check_vulnerabilities(devices)

      logging.info(f"Scan completed. {len(devices)} devices found.")

      # Ask if the user wants to perform another scan
      another_scan = input(f"{Color.YELLOW}Do you want to perform another scan? (y/n): {Color.RESET}").lower()
      if another_scan != 'y':
          print(f"{Color.CYAN}Thank you for using the Network Scanner. Goodbye!{Color.RESET}")
          break

      os.system('clear')  # Clear the screen for the next scan

if __name__ == "__main__":
  main()
