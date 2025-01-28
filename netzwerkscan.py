#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# erstellt von ELFO 

import argparse
import csv
import json
import logging
import os
import sys
import subprocess
import tempfile
from datetime import datetime
from typing import List, Dict, Any

import matplotlib.pyplot as plt
import networkx as nx
import nmap
import tqdm

if os.geteuid() != 0:
    print("Dieses Script benötigt Root-Rechte!")
    args = ["sudo", sys.executable] + sys.argv + [os.environ]
    os.execlpe("sudo", *args)

# Logging-Konfiguration
logging.basicConfig(
    filename="nmap_scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Terminal-Einstellungen
WIDTH = 160


class Color:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"


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
    print("*" * WIDTH)
    banner_centered = BANNER_TEXT.center(WIDTH)
    print(f"{Color.CYAN}{banner_centered}{Color.RESET}")
    print("*" * WIDTH)
    print()
    print(f"{Color.GREEN}Enhanced Network Scanner with Advanced Features:{Color.RESET}")
    print()
    print(f"{Color.YELLOW}Available command-line options:{Color.RESET}")
    print(f"{Color.YELLOW}-v, --verbose : Enable verbose output{Color.RESET}")
    print(f"{Color.YELLOW}-o, --output  : Specify output file base name{Color.RESET}")
    print()


class NetworkScanner:
    def __init__(self):
        self.vulnerability_database = {
            "ftp": {
                "anonymous_login": {
                    "severity": "High",
                    "description": "Anonymous FTP login enabled",
                    "recommendation": "Disable anonymous FTP access",
                },
                "clear_text": {
                    "severity": "Medium",
                    "description": "FTP transmits data in clear text",
                    "recommendation": "Use SFTP instead",
                },
            },
            "ssh": {
                "weak_cipher": {
                    "severity": "High",
                    "description": "Weak SSH ciphers enabled",
                    "recommendation": "Configure strong ciphers only",
                },
                "old_version": {
                    "severity": "Medium",
                    "description": "Running outdated SSH version",
                    "recommendation": "Update to latest version",
                },
            },
            "http": {
                "default_credentials": {
                    "severity": "Critical",
                    "description": "Default credentials might be in use",
                    "recommendation": "Change default passwords",
                },
                "ssl_vulnerable": {
                    "severity": "High",
                    "description": "Vulnerable SSL/TLS version",
                    "recommendation": "Update SSL/TLS configuration",
                },
            },
        }
        self.scan_profiles = {
            "1": {"name": "Quick Scan", "args": "-T4 -F"},
            "2": {"name": "Detailed Scan", "args": "-sS -sV -O -A -T4"},
            "3": {"name": "Vulnerability Scan", "args": "-sS -sV -A --script vuln"},
            "4": {"name": "Full Port Scan", "args": "-sS -sV -p- -T4"},
            "5": {"name": "Stealth Scan", "args": "-sS -T2 -f"},
        }

    def get_scan_configuration(self):
        print("\nVerfügbare Scan-Profile:")
        for key, profile in self.scan_profiles.items():
            print(f"{key}. {profile['name']}: {profile['args']}")

        while True:
            choice = input("\nWählen Sie ein Scan-Profil (1-5): ")
            if choice in self.scan_profiles:
                return self.scan_profiles[choice]["args"]
            print(
                f"{Color.RED}Ungültige Auswahl. Bitte wählen Sie eine Nummer zwischen 1 und 5.{Color.RESET}"
            )

    def scan_network(
        self, ip_range: str, nmap_arguments: str, verbose: bool = False
    ) -> List[Dict[str, Any]]:
        devices = []
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
                command = [
                    "nmap",
                    "-oX",
                    tmpfile.name,
                    ip_range,
                ] + nmap_arguments.split()
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )

                for line in tqdm.tqdm(
                    iter(process.stdout.readline, ""), desc="Scanning", unit=" hosts"
                ):
                    if verbose:
                        print(line, end="")

                process.wait()

                with open(tmpfile.name, "r") as xml_output:
                    nmap_output = xml_output.read()

            os.remove(tmpfile.name)

            nm = nmap.PortScanner()
            nm.analyse_nmap_xml_scan(nmap_output)

            for host in nm.all_hosts():
                device_info = self._process_host(nm, host)
                devices.append(device_info)

        except Exception as e:
            logging.error(f"Error during network scan: {str(e)}")
            print(f"{Color.RED}Error during scan: {str(e)}{Color.RESET}")

        return devices

    def _process_host(self, nm, host):
        mac = nm[host]["addresses"].get("mac", "Unknown")
        hostname = nm[host].hostname() or "Unknown"
        open_ports = []
        os_info = nm[host].get("osmatch", [{"name": "Unknown"}])[0]["name"]

        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                service = nm[host][proto][port]["name"]
                version = nm[host][proto][port].get("version", "")
                state = nm[host][proto][port]["state"]
                open_ports.append(f"{port}/{proto} {state} {service} {version}")

        return {
            "ip": host,
            "mac": mac,
            "hostname": hostname,
            "os": os_info,
            "open_ports": open_ports,
        }

    def enhanced_visualization(self, devices):
        G = nx.Graph()
        service_colors = {
            "http": "lightblue",
            "https": "green",
            "ftp": "red",
            "ssh": "yellow",
            "smb": "orange",
        }

        for device in devices:
            G.add_node(
                device["ip"],
                label=f"{device['hostname']}\n{device['ip']}\n{device['os']}",
                type="device",
            )

            for port in device["open_ports"]:
                service = port.split()[2]
                port_id = f"{device['ip']}:{port}"
                color = service_colors.get(service, "gray")
                G.add_node(port_id, label=port, type="port", color=color)
                G.add_edge(device["ip"], port_id)

        plt.figure(figsize=(15, 10))
        pos = nx.spring_layout(G, k=1, iterations=50)

        device_nodes = [
            n for n, attr in G.nodes(data=True) if attr.get("type") == "device"
        ]
        nx.draw_networkx_nodes(
            G,
            pos,
            nodelist=device_nodes,
            node_color="lightgreen",
            node_size=3000,
            alpha=0.7,
        )

        port_nodes = [n for n, attr in G.nodes(data=True) if attr.get("type") == "port"]
        port_colors = [G.nodes[n].get("color", "gray") for n in port_nodes]
        nx.draw_networkx_nodes(
            G,
            pos,
            nodelist=port_nodes,
            node_color=port_colors,
            node_size=2000,
            alpha=0.6,
        )

        nx.draw_networkx_edges(G, pos, alpha=0.5)
        labels = nx.get_node_attributes(G, "label")
        nx.draw_networkx_labels(G, pos, labels, font_size=8)

        plt.title("Network Topology with Services")
        plt.axis("off")
        plt.show()

    def enhanced_vulnerability_check(self, devices):
        findings = []
        for device in devices:
            device_findings = {
                "ip": device["ip"],
                "hostname": device["hostname"],
                "vulnerabilities": [],
            }

            for port in device["open_ports"]:
                service = port.split()[2].lower()
                if service in self.vulnerability_database:
                    for vuln_type, vuln_info in self.vulnerability_database[
                        service
                    ].items():
                        device_findings["vulnerabilities"].append(
                            {
                                "service": service,
                                "port": port,
                                "type": vuln_type,
                                "severity": vuln_info["severity"],
                                "description": vuln_info["description"],
                                "recommendation": vuln_info["recommendation"],
                            }
                        )

            if device_findings["vulnerabilities"]:
                findings.append(device_findings)

        return findings

    def generate_detailed_report(self, devices, vulnerability_findings):
        report = {
            "scan_summary": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_devices": len(devices),
                "total_vulnerabilities": sum(
                    len(f["vulnerabilities"]) for f in vulnerability_findings
                ),
            },
            "network_statistics": {"os_distribution": {}, "service_distribution": {}},
            "vulnerability_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "detailed_findings": vulnerability_findings,
            "devices": devices,
        }

        for device in devices:
            os = device["os"]
            report["network_statistics"]["os_distribution"][os] = (
                report["network_statistics"]["os_distribution"].get(os, 0) + 1
            )

            for port in device["open_ports"]:
                service = port.split()[2]
                report["network_statistics"]["service_distribution"][service] = (
                    report["network_statistics"]["service_distribution"].get(service, 0)
                    + 1
                )

        for finding in vulnerability_findings:
            for vuln in finding["vulnerabilities"]:
                severity = vuln["severity"].lower()
                report["vulnerability_summary"][severity] = (
                    report["vulnerability_summary"].get(severity, 0) + 1
                )

        return report

    def save_reports(self, report, base_filename):
        # JSON Report
        with open(f"{base_filename}.json", "w") as f:
            json.dump(report, f, indent=4)

        # CSV Device Report
        with open(f"{base_filename}_devices.csv", "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["ip", "hostname", "os", "mac", "open_ports"]
            )
            writer.writeheader()
            for device in report["devices"]:
                writer.writerow(
                    {
                        "ip": device["ip"],
                        "hostname": device["hostname"],
                        "os": device["os"],
                        "mac": device["mac"],
                        "open_ports": ", ".join(device["open_ports"]),
                    }
                )

        # CSV Vulnerability Report
        with open(f"{base_filename}_vulnerabilities.csv", "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "ip",
                    "service",
                    "severity",
                    "description",
                    "recommendation",
                ],
            )
            writer.writeheader()
            for finding in report["detailed_findings"]:
                for vuln in finding["vulnerabilities"]:
                    writer.writerow(
                        {
                            "ip": finding["ip"],
                            "service": vuln["service"],
                            "severity": vuln["severity"],
                            "description": vuln["description"],
                            "recommendation": vuln["recommendation"],
                        }
                    )

    def print_detailed_terminal_report(self, report):
        """Erstellt eine detaillierte Ausgabe im Terminal"""
        print(f"\n{Color.CYAN}{'=' * WIDTH}{Color.RESET}")
        print(f"{Color.GREEN}SCAN ZUSAMMENFASSUNG:{Color.RESET}")
        print(
            f"{Color.YELLOW}Zeitstempel:{Color.RESET} {report['scan_summary']['timestamp']}"
        )
        print(
            f"{Color.YELLOW}Geräte gefunden:{Color.RESET} {report['scan_summary']['total_devices']}"
        )
        print(
            f"{Color.YELLOW}Vulnerabilitäten gefunden:{Color.RESET} {report['scan_summary']['total_vulnerabilities']}"
        )

        print(f"\n{Color.CYAN}{'=' * WIDTH}{Color.RESET}")
        print(f"{Color.GREEN}NETZWERK STATISTIKEN:{Color.RESET}")

        print(f"\n{Color.YELLOW}OS Verteilung:{Color.RESET}")
        for os, count in report["network_statistics"]["os_distribution"].items():
            print(f"  - {os}: {count}")

        print(f"\n{Color.YELLOW}Dienst Verteilung:{Color.RESET}")
        for service, count in report["network_statistics"][
            "service_distribution"
        ].items():
            print(f"  - {service}: {count}")

        print(f"\n{Color.CYAN}{'=' * WIDTH}{Color.RESET}")
        print(f"{Color.GREEN}DETAILLIERTE GERÄTEINFORMATIONEN:{Color.RESET}")
        for device in report["devices"]:
            print(f"\n{Color.YELLOW}IP:{Color.RESET} {device['ip']}")
            print(f"{Color.YELLOW}Hostname:{Color.RESET} {device['hostname']}")
            print(f"{Color.YELLOW}MAC:{Color.RESET} {device['mac']}")
            print(f"{Color.YELLOW}OS:{Color.RESET} {device['os']}")
            print(f"{Color.YELLOW}Offene Ports:{Color.RESET}")
            for port in device["open_ports"]:
                print(f"  - {port}")

        print(f"\n{Color.CYAN}{'=' * WIDTH}{Color.RESET}")
        print(f"{Color.GREEN}VULNERABILITÄTEN:{Color.RESET}")
        for finding in report["detailed_findings"]:
            print(
                f"\n{Color.RED}Gerät {finding['ip']} ({finding['hostname']}):{Color.RESET}"
            )
            for vuln in finding["vulnerabilities"]:
                color = Color.RED if vuln["severity"] == "Critical" else Color.YELLOW
                print(
                    f"  {color}{vuln['severity']} - {vuln['service']} ({vuln['port']}):{Color.RESET}"
                )
                print(f"  Beschreibung: {vuln['description']}")
                print(f"  Empfehlung: {vuln['recommendation']}\n")

    def save_html_report(self, report, filename):
        """Erweitertes HTML-Reporting"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; }}
                .critical {{ color: #ff0000; }}
                .high {{ color: #ff6600; }}
                .medium {{ color: #ffcc00; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f5f5f5; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
            </style>
        </head>
        <body>
            <h1>Network Scan Report</h1>

            <div class="section">
                <h2>Scan Summary</h2>
                <p>Timestamp: {report["scan_summary"]["timestamp"]}</p>
                <p>Total Devices: {report["scan_summary"]["total_devices"]}</p>
                <p>Total Vulnerabilities: {report["scan_summary"]["total_vulnerabilities"]}</p>
            </div>

            <div class="section">
                <h2>Network Statistics</h2>
                <h3>OS Distribution</h3>
                <table>
                    <tr><th>Operating System</th><th>Count</th></tr>
                    {"".join(f"<tr><td>{os}</td><td>{count}</td></tr>" for os, count in report["network_statistics"]["os_distribution"].items())}
                </table>

                <h3>Service Distribution</h3>
                <table>
                    <tr><th>Service</th><th>Count</th></tr>
                    {"".join(f"<tr><td>{service}</td><td>{count}</td></tr>" for service, count in report["network_statistics"]["service_distribution"].items())}
                </table>
            </div>

            <div class="section">
                <h2>Devices</h2>
                {"".join(self._generate_device_html(device) for device in report["devices"])}
            </div>

            <div class="section">
                <h2>Vulnerabilities</h2>
                {"".join(self._generate_vuln_html(finding) for finding in report["detailed_findings"])}
            </div>
        </body>
        </html>
        """
        with open(f"{filename}.html", "w") as f:
            f.write(html_content)

    def _generate_device_html(self, device):
        return f"""
        <div class="device">
            <h3>{device["ip"]} ({device["hostname"]})</h3>
            <p>MAC: {device["mac"]}<br>OS: {device["os"]}</p>
            <h4>Open Ports:</h4>
            <ul>
                {"".join(f"<li>{port}</li>" for port in device["open_ports"])}
            </ul>
        </div>
        """

    def _generate_vuln_html(self, finding):
        return f"""
        <div class="vulnerability">
            <h3>{finding["ip"]} ({finding["hostname"]})</h3>
            <table>
                <tr><th>Service</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>
                {
            "".join(
                f'''
                <tr class="{vuln["severity"].lower()}">
                    <td>{vuln["service"]} ({vuln["port"]})</td>
                    <td>{vuln["severity"]}</td>
                    <td>{vuln["description"]}</td>
                    <td>{vuln["recommendation"]}</td>
                </tr>
                '''
                for vuln in finding["vulnerabilities"]
            )
        }
            </table>
        </div>
        """


def main():
    scanner = NetworkScanner()
    parser = argparse.ArgumentParser(description="Network Scanner using Nmap")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-o",
        "--output",
        help='Specify base filename for saving results (e.g., "scan_results")',
    )
    args = parser.parse_args()

    while True:
        print_banner()
        ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
        nmap_arguments = scanner.get_scan_configuration()
        devices = scanner.scan_network(ip_range, nmap_arguments, args.verbose)
        vulnerability_findings = scanner.enhanced_vulnerability_check(devices)
        report = scanner.generate_detailed_report(devices, vulnerability_findings)

        # Terminal Report
        scanner.print_detailed_terminal_report(report)

        # Save Reports
        if args.output:
            scanner.save_reports(report, args.output)
            scanner.save_html_report(report, args.output)

        # Visualization
        scanner.enhanced_visualization(devices)

        another_scan = input("Do you want to perform another scan? (y/n): ").lower()
        if another_scan != "y":
            break


if __name__ == "__main__":
    main()
