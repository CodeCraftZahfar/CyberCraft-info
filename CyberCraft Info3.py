import socket
import subprocess
import nmap
import requests
from bs4 import BeautifulSoup
import pyfiglet
import os
import warnings
import re
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def dns_lookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        return f"Error: {e}"

def whois_lookup(domain):
    try:
        # Execute whois command and capture the output
        process = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = process.communicate()
        return output.decode('utf-8')
    except Exception as e:
        return f"Error: {e}"

def port_scan(ip_address):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip_address, arguments='-p 1-1000')  # Scan first 1000 ports
        open_ports = {}
        for host in scanner.all_hosts():
            open_ports[host] = []
            for port in scanner[host]['tcp']:
                if scanner[host]['tcp'][port]['state'] == 'open':
                    open_ports[host].append((port, scanner[host]['tcp'][port]['name']))
        return open_ports
    except Exception as e:
        return {"error": f"Error: {e}"}

def find_email_addresses(html_content):
    # Regular expression to match email addresses
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    # Find all email addresses in the HTML content
    emails = re.findall(email_regex, html_content)
    return emails

def web_scrape(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        page_title = soup.title.text if soup.title else None
        links = [link.get('href') for link in soup.find_all('a')]
        # Find email addresses in the HTML content
        email_addresses = find_email_addresses(response.text)
        return {"title": page_title, "links": links, "emails": email_addresses}
    except Exception as e:
        return {"error": f"Error: {e}"}

def generate_html_report(domain, ip_address, whois_info, open_ports, webpage_info):
    html_report = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyberCraft Info Report - {domain}</title>
    </head>
    <body>
        <h1>CyberCraft Info Report - {domain}</h1>
        <h2>Domain Information</h2>
        <p>Domain: {domain}</p>
        <p>IP Address: {ip_address}</p>
    """

    html_report += "<h2>Whois Information</h2>"
    html_report += f"<pre>{whois_info}</pre>"

    if "error" in open_ports:
        html_report += f"<p>Port Scan Error: {open_ports['error']}</p>"
    else:
        html_report += "<h2>Open Ports</h2>"
        html_report += "<ul>"
        for host, ports in open_ports.items():
            html_report += f"<li><strong>Host:</strong> {host}"
            html_report += "<ul>"
            for port, service in ports:
                html_report += f"<li><strong>Port {port}:</strong> {service}</li>"
            html_report += "</ul></li>"
        html_report += "</ul>"

    if "error" in webpage_info:
        html_report += f"<p>Web Scraping Error: {webpage_info['error']}</p>"
    else:
        html_report += "<h2>Webpage Information</h2>"
        html_report += f"<p><strong>Title:</strong> {webpage_info['title']}</p>"
        html_report += "<p><strong>Links:</strong></p>"
        html_report += "<ul>"
        for link in webpage_info['links']:
            html_report += f"<li>{link}</li>"
        html_report += "</ul>"

        # Add email addresses to the report
        html_report += "<h2>Email Addresses</h2>"
        html_report += "<ul>"
        for email in webpage_info['emails']:
            html_report += f"<li>{email}</li>"
        html_report += "</ul>"

    html_report += """
    </body>
    </html>
    """

    return html_report

def generate_pdf_report(domain, ip_address, whois_info, open_ports, webpage_info):
    pdf_file = f"cybercrafter_info_report_{domain}.pdf"
    c = canvas.Canvas(pdf_file, pagesize=letter)
    c.drawString(100, 750, f"CyberCraft Info Report - {domain}")

    y = 700
    c.drawString(100, y, "Domain Information")
    c.drawString(120, y-20, f"Domain: {domain}")
    c.drawString(120, y-40, f"IP Address: {ip_address}")

    y -= 80
    c.drawString(100, y, "Whois Information")
    whois_info_lines = whois_info.split("\n")
    for line in whois_info_lines:
        y -= 20
        c.drawString(120, y, line[:80])

    if "error" in open_ports:
        y -= 40
        c.drawString(100, y, f"Port Scan Error: {open_ports['error']}")
    else:
        y -= 40
        c.drawString(100, y, "Open Ports")
        for host, ports in open_ports.items():
            y -= 20
            c.drawString(120, y, f"Host: {host}")
            for port, service in ports:
                y -= 20
                c.drawString(140, y, f"Port {port}: {service}")

    if "error" in webpage_info:
        y -= 40
        c.drawString(100, y, f"Web Scraping Error: {webpage_info['error']}")
    else:
        y -= 40
        c.drawString(100, y, "Webpage Information")
        y -= 20
        c.drawString(120, y, f"Title: {webpage_info['title']}")
        y -= 20
        c.drawString(120, y, "Links:")
        for link in webpage_info['links']:
            y -= 20
            c.drawString(140, y, link)

        y -= 40
        c.drawString(100, y, "Email Addresses")
        for email in webpage_info['emails']:
            y -= 20
            c.drawString(120, y, email)

    c.save()
    return pdf_file

def save_report(report, domain, format, code):
    folder_path = os.path.expanduser("~/Documents")
    file_name = f"{folder_path}/cybercrafter_info_report_{domain}_{code}.{format}"
    with open(file_name, "w") as file:
        file.write(report)

def main():
    ascii_banner = pyfiglet.figlet_format("CyberCraft Info", font="slant")
    print(ascii_banner)

    domain = input("Enter the domain name: ")

    ip_address = dns_lookup(domain)
    whois_info = whois_lookup(domain)
    open_ports = port_scan(ip_address)
    url = f"http://{domain}"
    webpage_info = web_scrape(url)

    code = input("Enter the code name for this report: ")

    choice = input("Choose the format to save the report (PDF/HTML): ").lower()

    if choice == "pdf":
        report = generate_pdf_report(domain, ip_address, whois_info, open_ports, webpage_info)
        save_report(report, domain, "pdf", code)
    elif choice == "html":
        report = generate_html_report(domain, ip_address, whois_info, open_ports, webpage_info)
        save_report(report, domain, "html", code)
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main()
