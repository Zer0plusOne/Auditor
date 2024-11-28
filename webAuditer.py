#!/usr/bin/env python3

import requests
import socket
import ssl
import sys
import nmap
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

class WebAuditor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.results = {}
        self.vulnerable_versions = []  # Almacenar vulnerabilidades encontradas

    def run_full_audit(self):
        print(f"[+] Iniciando auditoría completa de {self.target_url}")
        self.check_ssl()
        self.check_headers()
        self.check_open_ports_and_versions()
        self.get_whois_info()
        self.check_common_vulnerabilities()
        self.crawl_for_sensitive_files()
        self.generate_report()

    def check_ssl(self):
        print("[*] Verificando certificado SSL...")
        try:
            hostname = self.target_url.split("//")[-1].split("/")[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': cert['notAfter'],
                        'version': cert['version']
                    }
        except Exception as e:
            self.results['ssl'] = f"Error: {str(e)}"

    def check_headers(self):
        print("[*] Analizando headers de seguridad...")
        try:
            response = requests.get(self.target_url, headers=self.headers)
            headers = response.headers
            security_headers = {
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy')
            }
            self.results['security_headers'] = security_headers
        except Exception as e:
            self.results['security_headers'] = f"Error: {str(e)}"

    def check_open_ports_and_versions(self):
        print("[*] Escaneando puertos y detectando versiones...")
        try:
            nm = nmap.PortScanner()
            hostname = self.target_url.split("//")[-1].split("/")[0]
            nm.scan(hostname, '21-443', arguments='-sV')  # Agregar argumento -sV para detección de versiones

            open_ports_info = {}
            for host in nm.all_hosts():
                open_ports_info[host] = []
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        service = nm[host][proto][port]
                        open_ports_info[host].append({
                            'port': port,
                            'service': service['name'],
                            'version': service['version']
                        })

            self.results['open_ports'] = open_ports_info

            # Aquí simulamos una verificación de vulnerabilidades de las versiones
            for host in open_ports_info:
                for service_info in open_ports_info[host]:
                    # Simulación de verificación de vulnerabilidades
                    pass
        except Exception as e:
            self.results['open_ports'] = f"Error: {str(e)}"

    def get_whois_info(self):
        print("[*] Obteniendo información WHOIS...")
        try:
            domain = self.target_url.split("//")[-1].split("/")[0]
            whois_info = whois.whois(domain)
            self.results['whois'] = whois_info
        except Exception as e:
            self.results['whois'] = f"Error: {str(e)}"

    def check_common_vulnerabilities(self):
        print("[*] Verificando vulnerabilidades comunes...")
        # Implementación de la verificación de vulnerabilidades comunes
        pass

    def crawl_for_sensitive_files(self):
        print("[*] Buscando archivos sensibles...")
        try:
            response = requests.get(self.target_url, headers=self.headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            links = []
            for link in soup.find_all(['a', 'link', 'script', 'img']):
                href = link.get('href') or link.get('src')
                if href:
                    links.append(urljoin(self.target_url, href))

            self.results['found_files'] = links
        except Exception as e:
            self.results['found_files'] = f"Error: {str(e)}"

    def generate_report(self):
        print("\n[+] Generando reporte...")
        report = f"""
        Web Security Audit Report
        ========================
        Target: {self.target_url}
        Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        SSL Certificate Information:
        --------------------------
        {self.results.get('ssl', 'No SSL information available')}
        Security Headers:
        ---------------
        {self.results.get('security_headers', 'No header information available')}
        Open Ports and Detected Services:
        --------------------------------
        {self.results.get('open_ports', 'No port information available')}
        WHOIS Information:
        ----------------
        {self.results.get('whois', 'No WHOIS information available')}
        Potentially Vulnerable Paths:
        --------------------------
        {self.results.get('vulnerable_paths', 'No vulnerability information available')}
        Detected Vulnerabilities on Protocol Versions:
        ---------------------------------------------
        {self.vulnerable_versions or 'No known vulnerabilities detected for service versions.'}
        Found Files:
        -----------
        {self.results.get('found_files', 'No files found')}
        """
        # Guardar el reporte en un archivo
        with open('audit_report.txt', 'w') as report_file:
            report_file.write(report)

def main():
    if len(sys.argv) != 2:
        print("Uso: python main.py <URL>")
        sys.exit(1)

    target_url = sys.argv[1]
    auditor = WebAuditor(target_url)
    auditor.run_full_audit()

if __name__ == "__main__":
    main()