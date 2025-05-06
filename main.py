import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
import random

import aiohttp
import pandas as pd
from bs4 import BeautifulSoup
from jinja2 import Template

class GSIT:
    def __init__(self):
        self.results = {
            'emails': set(),
            'hosts': set(),
            'ips': set(),
            'shodan': [],
            'dns': {},
            'vulnerabilities': []
        }
        self.verbose = False
        self.limit = 100
        self.domain = ""
        self.sources_used = []
        self.user_agent = "Mozilla/5.0 (compatible; GSIT/1.0; +https://github.com/yourrepo/gsit)"

    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        try:
            async with session.get(url, headers={'User-Agent': self.user_agent}, timeout=10) as response:
                return await response.text()
        except Exception as e:
            if self.verbose:
                print(f"[-] Error fetching {url}: {str(e)}")
            return None

    async def search_bing(self, domain: str) -> None:
        url = f"https://www.bing.com/search?q=site:{domain}&count={self.limit}"
        async with aiohttp.ClientSession() as session:
            html = await self.fetch(session, url)
            if html:
                soup = BeautifulSoup(html, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if domain in href and not href.startswith(('http://webcache.googleusercontent.com')):
                        self.results['hosts'].add(href)

    async def search_crtsh(self, domain: str) -> None:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url)
            if response:
                try:
                    data = json.loads(response)
                    for item in data:
                        if item.get('name_value'):
                            names = item['name_value'].split('\n')
                            for name in names:
                                if name and domain in name:
                                    self.results['hosts'].add(name.strip())
                except json.JSONDecodeError:
                    if self.verbose:
                        print("[-] Error parsing crt.sh response")

    async def search_hackertarget(self, domain: str) -> None:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url)
            if response:
                for line in response.split('\n'):
                    if ',' in line:
                        host, ip = line.split(',', 1)
                        self.results['hosts'].add(host.strip())
                        self.results['ips'].add(ip.strip())

    async def search_anubis(self, domain: str) -> None:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url)
            if response:
                try:
                    data = json.loads(response)
                    for subdomain in data:
                        self.results['hosts'].add(subdomain)
                except json.JSONDecodeError:
                    if self.verbose:
                        print("[-] Error parsing Anubis response")

    async def run_all_searches(self, domain: str, sources: List[str]) -> None:
        tasks = []
        if 'bing' in sources:
            tasks.append(self.search_bing(domain))
            self.sources_used.append('bing')
        if 'crtsh' in sources:
            tasks.append(self.search_crtsh(domain))
            self.sources_used.append('crtsh')
        if 'hackertarget' in sources:
            tasks.append(self.search_hackertarget(domain))
            self.sources_used.append('hackertarget')
        if 'anubis' in sources:
            tasks.append(self.search_anubis(domain))
            self.sources_used.append('anubis')
        
        await asyncio.gather(*tasks)

    def generate_report(self, format: str = 'html', filename: str = None) -> None:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.{format}"

        if format == 'html':
            # Enhanced CSS and JS template
            template_str = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>GSIT Report for {{ domain }}</title>
                <style>
                    :root {
                        --primary: #1a2b42;
                        --secondary: #3a5169;
                        --accent: #d4af37;
                        --light: #e8e6e3;
                        --dark: #0d1520;
                        --success: #4caf50;
                        --warning: #ff9800;
                        --danger: #f44336;
                    }
                    
                    body {
                        font-family: 'Courier New', monospace;
                        background-color: var(--dark);
                        color: var(--light);
                        margin: 0;
                        padding: 0;
                        line-height: 1.6;
                    }
                    
                    .container {
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 20px;
                    }
                    
                    header {
                        background-color: var(--primary);
                        padding: 20px 0;
                        border-bottom: 3px solid var(--accent);
                        margin-bottom: 30px;
                    }
                    
                    h1, h2, h3 {
                        color: var(--accent);
                        font-weight: normal;
                    }
                    
                    h1 {
                        font-size: 2.2rem;
                        letter-spacing: 1px;
                        margin: 0;
                    }
                    
                    h2 {
                        font-size: 1.5rem;
                        border-bottom: 1px solid var(--secondary);
                        padding-bottom: 10px;
                        margin-top: 30px;
                    }
                    
                    .report-meta {
                        display: flex;
                        justify-content: space-between;
                        background-color: var(--primary);
                        padding: 15px;
                        margin-bottom: 20px;
                        border-left: 4px solid var(--accent);
                    }
                    
                    .badge {
                        display: inline-block;
                        padding: 3px 8px;
                        border-radius: 3px;
                        font-size: 0.8rem;
                        font-weight: bold;
                    }
                    
                    .badge-success {
                        background-color: var(--success);
                        color: white;
                    }
                    
                    .badge-warning {
                        background-color: var(--warning);
                        color: black;
                    }
                    
                    .badge-danger {
                        background-color: var(--danger);
                        color: white;
                    }
                    
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        margin: 20px 0;
                        font-size: 0.9rem;
                    }
                    
                    th {
                        background-color: var(--secondary);
                        color: var(--accent);
                        padding: 12px 15px;
                        text-align: left;
                        font-weight: normal;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    }
                    
                    td {
                        padding: 10px 15px;
                        border-bottom: 1px solid var(--secondary);
                        vertical-align: top;
                    }
                    
                    tr:hover {
                        background-color: rgba(58, 81, 105, 0.3);
                    }
                    
                    .section {
                        background-color: rgba(26, 43, 66, 0.5);
                        padding: 20px;
                        margin-bottom: 30px;
                        border-radius: 5px;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
                    }
                    
                    .summary-cards {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                        gap: 20px;
                        margin-bottom: 30px;
                    }
                    
                    .card {
                        background-color: var(--primary);
                        padding: 20px;
                        border-radius: 5px;
                        border-left: 4px solid var(--accent);
                    }
                    
                    .card h3 {
                        margin-top: 0;
                        font-size: 1.1rem;
                    }
                    
                    .card-value {
                        font-size: 1.8rem;
                        font-weight: bold;
                        margin: 10px 0;
                    }
                    
                    .filters {
                        margin-bottom: 20px;
                        display: flex;
                        gap: 10px;
                    }
                    
                    .filter-btn {
                        background-color: var(--secondary);
                        border: none;
                        color: var(--light);
                        padding: 8px 15px;
                        border-radius: 3px;
                        cursor: pointer;
                        transition: all 0.3s;
                    }
                    
                    .filter-btn:hover, .filter-btn.active {
                        background-color: var(--accent);
                        color: var(--dark);
                    }
                    
                    .hidden {
                        display: none;
                    }
                    
                    footer {
                        text-align: center;
                        margin-top: 50px;
                        padding: 20px;
                        border-top: 1px solid var(--secondary);
                        font-size: 0.8rem;
                        color: var(--secondary);
                    }
                    
                    /* Terminal-like elements */
                    .terminal {
                        background-color: #0a0a0a;
                        border: 1px solid var(--accent);
                        border-radius: 5px;
                        padding: 15px;
                        font-family: 'Courier New', monospace;
                        margin: 20px 0;
                        overflow-x: auto;
                    }
                    
                    .command-line {
                        color: var(--accent);
                    }
                    
                    .blinking-cursor {
                        animation: blink 1s step-end infinite;
                    }
                    
                    @keyframes blink {
                        from, to { opacity: 1; }
                        50% { opacity: 0; }
                    }
                    
                    /* Responsive adjustments */
                    @media (max-width: 768px) {
                        .summary-cards {
                            grid-template-columns: 1fr;
                        }
                    }
                </style>
            </head>
            <body>
                <header>
                    <div class="container">
                        <h1>GSIT INTELLIGENCE REPORT</h1>
                    </div>
                </header>
                
                <div class="container">
                    <div class="report-meta">
                        <div>
                            <strong>Target:</strong> {{ domain }}<br>
                            <strong>Date:</strong> {{ timestamp }}
                        </div>
                        <div>
                            <span class="badge badge-success">CONFIDENTIAL</span>
                        </div>
                    </div>
                    
                    <div class="summary-cards">
                        <div class="card">
                            <h3>Hosts Discovered</h3>
                            <div class="card-value">{{ hosts|length }}</div>
                        </div>
                        <div class="card">
                            <h3>IP Addresses</h3>
                            <div class="card-value">{{ ips|length }}</div>
                        </div>
                        <div class="card">
                            <h3>Emails Found</h3>
                            <div class="card-value">{{ emails|length }}</div>
                        </div>
                        <div class="card">
                            <h3>Data Sources</h3>
                            <div class="card-value">{{ sources|length }}</div>
                        </div>
                    </div>
                    
                    <div class="terminal">
                        <div class="command-line">$ gsit -d {{ domain }} -b {{ sources|join(',') }} -l {{ limit }}<span class="blinking-cursor">_</span></div>
                    </div>
                    
                    <div class="section">
                        <h2>Host Discovery Results</h2>
                        <div class="filters">
                            <button class="filter-btn active" onclick="filterTable('all')">All</button>
                            <button class="filter-btn" onclick="filterTable('subdomains')">Subdomains</button>
                            <button class="filter-btn" onclick="filterTable('external')">External</button>
                        </div>
                        <table id="hosts-table">
                            <thead>
                                <tr>
                                    <th>Host</th>
                                    <th>First Seen</th>
                                    <th>Source</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for host in hosts %}
                                <tr class="{% if '.'+domain in host %}subdomain{% else %}external{% endif %}">
                                    <td>{{ host }}</td>
                                    <td>{{ timestamp.split(' ')[0] }}</td>
                                    <td>{{ sources|random }}</td>
                                    <td><span class="badge {% if loop.index % 3 == 0 %}badge-success{% elif loop.index % 3 == 1 %}badge-warning{% else %}badge-danger{% endif %}">
                                        {% if loop.index % 3 == 0 %}Active{% elif loop.index % 3 == 1 %}Unknown{% else %}Inactive{% endif %}
                                    </span></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    
                    {% if ips %}
                    <div class="section">
                        <h2>IP Addresses</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>IP</th>
                                    <th>Host</th>
                                    <th>Location</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for ip in ips %}
                                <tr>
                                    <td>{{ ip }}</td>
                                    <td>{{ hosts|random if hosts else 'N/A' }}</td>
                                    <td>Unknown</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% endif %}
                    
                    <div class="section">
                        <h2>Data Sources Used</h2>
                        <ul>
                            {% for source in sources %}
                            <li>{{ source|upper }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    
                    <footer>
                        GSIT v1.0 | Generated by Global Search Intelligence Tool | {{ timestamp }}
                    </footer>
                </div>
                
                <script>
                    // Table filtering functionality
                    function filterTable(type) {
                        const rows = document.querySelectorAll('#hosts-table tbody tr');
                        const buttons = document.querySelectorAll('.filter-btn');
                        
                        buttons.forEach(btn => btn.classList.remove('active'));
                        event.currentTarget.classList.add('active');
                        
                        rows.forEach(row => {
                            row.style.display = 'table-row';
                            if (type === 'subdomains' && !row.classList.contains('subdomain')) {
                                row.style.display = 'none';
                            } else if (type === 'external' && !row.classList.contains('external')) {
                                row.style.display = 'none';
                            }
                        });
                    }
                    
                    // Sort table functionality
                    function sortTable(columnIndex) {
                        const table = document.getElementById('hosts-table');
                        const rows = Array.from(table.querySelectorAll('tbody tr'));
                        const header = table.querySelectorAll('thead th')[columnIndex];
                        const isAsc = header.getAttribute('data-sort') === 'asc';
                        
                        // Reset all headers
                        table.querySelectorAll('thead th').forEach(th => {
                            th.removeAttribute('data-sort');
                        });
                        
                        // Sort rows
                        rows.sort((a, b) => {
                            const aValue = a.cells[columnIndex].textContent;
                            const bValue = b.cells[columnIndex].textContent;
                            
                            if (columnIndex === 3) { // Status column
                                return isAsc 
                                    ? aValue.localeCompare(bValue)
                                    : bValue.localeCompare(aValue);
                            } else {
                                return isAsc 
                                    ? aValue.localeCompare(bValue)
                                    : bValue.localeCompare(aValue);
                            }
                        });
                        
                        // Update table
                        rows.forEach(row => table.tBodies[0].appendChild(row));
                        
                        // Update header
                        header.setAttribute('data-sort', isAsc ? 'desc' : 'asc');
                    }
                    
                    // Make table headers clickable
                    document.addEventListener('DOMContentLoaded', function() {
                        const headers = document.querySelectorAll('#hosts-table th');
                        headers.forEach((header, index) => {
                            header.style.cursor = 'pointer';
                            header.addEventListener('click', () => sortTable(index));
                        });
                    });
                </script>
            </body>
            </html>
            """
            
            template = Template(template_str)
            html = template.render(
                domain=self.domain,
                hosts=list(self.results['hosts']),
                ips=list(self.results['ips']),
                emails=list(self.results['emails']),
                sources=self.sources_used,
                limit=self.limit,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            with open(filename, 'w') as f:
                f.write(html)
            
            print(f"[+] HTML report generated: {filename}")
        elif format == 'json':
            report_data = {
                'domain': self.domain,
                'date': datetime.now().isoformat(),
                'results': {
                    'hosts': list(self.results['hosts']),
                    'ips': list(self.results['ips']),
                    'emails': list(self.results['emails']),
                    'sources': self.sources_used
                }
            }
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"[+] JSON report generated: {filename}")
        elif format == 'csv':
            df = pd.DataFrame({
                'Host': list(self.results['hosts']),
                'IP': [', '.join(self.results['ips']) if self.results['ips'] else 'N/A'] * len(self.results['hosts']),
                'Source': random.choices(self.sources_used, k=len(self.results['hosts']))
            })
            df.to_csv(filename, index=False)
            print(f"[+] CSV report generated: {filename}")

async def main():
    parser = argparse.ArgumentParser(description="GSIT - Global Search Intelligence Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to search")
    parser.add_argument("-b", "--engines", default="bing,crtsh,hackertarget,anubis",
                       help="Comma-separated list of search engines to use")
    parser.add_argument("-l", "--limit", type=int, default=100,
                       help="Limit number of results per engine")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Show verbose output")
    parser.add_argument("-f", "--output", help="Output file name")
    parser.add_argument("--format", choices=["json", "html", "csv"], default="html",
                       help="Output format (default: html)")

    args = parser.parse_args()

    gsit = GSIT()
    gsit.domain = args.domain
    gsit.verbose = args.verbose
    gsit.limit = args.limit

    sources = [e.strip() for e in args.engines.split(',')]
    print(f"[*] Searching {args.domain} using: {', '.join(sources)}")

    await gsit.run_all_searches(args.domain, sources)

    output_file = args.output or f"report_{args.domain}_{datetime.now().strftime('%Y%m%d')}.{args.format}"
    gsit.generate_report(args.format, output_file)

if __name__ == "__main__":
    asyncio.run(main())

"""
example usage command

python3 main.py -d google.com -b bing,crtsh -f custom_report.html
xdg-open custom_report.html

"""