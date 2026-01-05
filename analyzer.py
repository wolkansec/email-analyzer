import sys
import email
from email import policy
from email.parser import BytesParser


def parse_eml(file_path):
    """
    .eml dosyasını okur ve email.message.EmailMessage nesnesi döner.
    """
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

import re
import pprint
from typing import Dict, Any, List
from termcolor import cprint, colored
import hashlib
from urllib.parse import urlparse
from html.parser import HTMLParser

def analyze_headers(msg) -> Dict[str, Any]:
    results = {}
    # 1. Date ve Subject bilgilerini al
    results['Date'] = msg.get('Date', 'Not Found')
    results['Subject'] = msg.get('Subject', 'Not Found')
    
    # 2. Authentication-Results'tan SPF, DKIM, DMARC sonucu çek
    auth_res = msg.get('Authentication-Results', '')
    spf_match = re.search(r"spf=(\w+)", auth_res)
    dkim_match = re.search(r"dkim=(\w+)", auth_res)
    dmarc_match = re.search(r"dmarc=(\w+)", auth_res)
    action_match = re.search(r"action=(\w+)", auth_res)
    results['SPF'] = spf_match.group(1) if spf_match else 'Not Found'
    results['DKIM'] = dkim_match.group(1) if dkim_match else 'Not Found'
    results['DMARC'] = dmarc_match.group(1) if dmarc_match else 'Not Found'
    results['ACTION'] = action_match.group(1) if action_match else 'Not Found'
    
    # 3. Kimlik (From, Reply-To, Return-Path) tutarsızlık kontrolü
    from_addr = msg.get('From', '').strip().lower()
    reply_to = msg.get('Reply-To', '').strip().lower()
    return_path = msg.get('Return-Path', '').strip().lower()
    id_consistency = (from_addr == reply_to == return_path)
    results['From'] = from_addr
    results['Reply-To'] = reply_to if reply_to else 'Not present'
    results['Return-Path'] = return_path if return_path else 'Not present'

    # 4. Received headerları ve IP adresleri
    received_headers = msg.get_all('Received', [])
    ip_regex = r'(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})'
    ips = []
    for header in received_headers:
        found_ips = re.findall(ip_regex, header)
        ips.extend(found_ips)
    results['All Received IPs'] = ips
    results['Original IP'] = ips[-1] if ips else 'Not Found'

    # 5. Çıktı - belirtilen sırayla
    from termcolor import cprint
    cprint("\n=== HEADER ANALYSIS ===", "blue", attrs=["bold"])
    
    # Belirtilen sırayla çıktı ver
    output_order = ['Date', 'Subject', 'From', 'Reply-To', 'Return-Path', 'Original IP', 'All Received IPs']
    for key in output_order:
        if key in results:
            val = results[key]
            print(colored(f"{key}:", "cyan"), val)
    
    # Diğer alanları da göster (SPF, DKIM, DMARC)
    for key in ['SPF', 'DKIM', 'DMARC', 'ACTION']:
        if key in results:
            print(colored(f"{key}:", "cyan"), results[key])
    
    return results

def extract_urls(msg) -> Dict[str, Any]:
    """
    Gövdeden tüm URL ve domainleri çıkarır.
    HTML ve text içerikten URL'leri toplar.
    """
    urls = []
    domains = []
    html_body = ''
    plain_body = ''
    
    # HTML ve text içerikleri çıkar
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/html':
                html_body += part.get_payload(decode=True).decode(errors="ignore")
            elif content_type == 'text/plain':
                plain_body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        content_type = msg.get_content_type()
        if content_type == 'text/html':
            html_body = msg.get_payload(decode=True).decode(errors="ignore")
        elif content_type == 'text/plain':
            plain_body = msg.get_payload(decode=True).decode(errors="ignore")
    
    # HTML içerikten href attribute'larını çıkar
    href_pattern = r'href=["\']([^"\']+)["\']'
    html_urls = re.findall(href_pattern, html_body, re.IGNORECASE)
    urls.extend(html_urls)
    
    # Text içerikten URL pattern'lerini bul (http/https)
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    text_urls = re.findall(url_pattern, plain_body, re.IGNORECASE)
    urls.extend(text_urls)
    
    # HTML içerikten de URL pattern'lerini bul
    html_text_urls = re.findall(url_pattern, html_body, re.IGNORECASE)
    urls.extend(html_text_urls)
    
    # Tekrarları kaldır ve domain'leri çıkar
    urls = list(set(urls))
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.append(parsed.netloc)
        except:
            pass
    
    domains = list(set(domains))
    
    return {'urls': urls, 'domains': domains}

def defang_indicators(indicators: List[str]) -> List[str]:
    defanged = []
    for indicator in indicators:
        if not indicator:
            continue
        # IP adresi kontrolü
        ip_pattern = r'^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})$'
        if re.match(ip_pattern, indicator):
            # IP'yi defang et: 192.168.1.1 -> 192[.]168[.]1[.]1
            defanged_ip = indicator.replace('.', '[.]')
            defanged.append(defanged_ip)
        else:
            # URL'yi defang et
            defanged_url = indicator
            # Önce :// kısmını değiştir
            if '://' in defanged_url:
                defanged_url = defanged_url.replace('://', '[://]')
            # Sonra domain kısmındaki noktaları değiştir
            # Sadece domain kısmındaki noktaları değiştir (path'teki noktaları değil)
            if '[://]' in defanged_url:
                parts = defanged_url.split('[://]', 1)
                scheme = parts[0]
                rest = parts[1]
                # Domain kısmını bul (ilk / veya ? veya # öncesi)
                domain_end = len(rest)
                for char in ['/', '?', '#']:
                    idx = rest.find(char)
                    if idx != -1 and idx < domain_end:
                        domain_end = idx
                domain = rest[:domain_end]
                path = rest[domain_end:]
                # Domain içindeki noktaları değiştir
                domain = domain.replace('.', '[.]')
                defanged_url = scheme + '[://]' + domain + path
            else:
                # Eğer :// yoksa, sadece noktaları değiştir (domain olabilir)
                defanged_url = defanged_url.replace('.', '[.]')
            defanged.append(defanged_url)
    return defanged

# --- Ek Analizi ---
def analyze_attachments(msg) -> Dict[str, Any]:
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            # Ek dosyası kontrolü (Content-Disposition: attachment)
            content_disposition = part.get('Content-Disposition', '')
            if 'attachment' in content_disposition.lower() or part.get_filename():
                filename = part.get_filename() or 'unnamed'
                payload = part.get_payload(decode=True)
                
                if payload:
                    # MD5 hash
                    md5_hash = hashlib.md5(payload).hexdigest()
                    # SHA256 hash
                    sha256_hash = hashlib.sha256(payload).hexdigest()
                    
                    attachments.append({
                        'filename': filename,
                        'md5': md5_hash,
                        'sha256': sha256_hash,
                        'size': len(payload)
                    })
    
    return {'attachments': attachments}

# --- Risk Skoru Hesaplama ---
def calculate_risk_score(headers: Dict[str, Any]) -> tuple:
    """
    Risk skorunu hesaplar (0-100 arası, yüksek = riskli)
    Returns: (score, risk_level, triggers)
    """
    score = 0
    triggers = []
    
    # SPF kontrolü
    spf = str(headers.get('SPF', '')).lower()
    if spf in ('fail', 'softfail', 'temperror', 'permerror'):
        score += 20
        triggers.append(f"SPF {spf.upper()}")
    elif spf == 'not found':
        score += 10
        triggers.append("SPF Not Found")
    
    # DKIM kontrolü
    dkim = str(headers.get('DKIM', '')).lower()
    if dkim in ('fail', 'none', 'not found'):
        score += 20
        triggers.append(f"DKIM {dkim.upper()}")
    
    # DMARC kontrolü
    dmarc = str(headers.get('DMARC', '')).lower()
    if dmarc in ('fail', 'quarantine', 'reject'):
        score += 20
        triggers.append(f"DMARC {dmarc.upper()}")
    elif dmarc == 'not found':
        score += 10
        triggers.append("DMARC Not Found")
    
    # ACTION kontrolü
    action = str(headers.get('ACTION', '')).lower()
    if action not in ('none', 'not found', ''):
        score += 10
        triggers.append(f"ACTION: {action.upper()}")
    
    # From vs Reply-To tutarsızlığı
    from_addr = str(headers.get('From', '')).lower()
    reply_to = str(headers.get('Reply-To', '')).lower()
    if reply_to and reply_to != 'not present' and from_addr != reply_to:
        score += 15
        triggers.append("From ≠ Reply-To")
    
    # From vs Return-Path tutarsızlığı
    return_path = str(headers.get('Return-Path', '')).lower()
    if return_path and return_path != 'not present' and from_addr != return_path:
        score += 15
        triggers.append("From ≠ Return-Path")
    
    # Risk seviyesi belirleme
    if score >= 70:
        risk_level = "CRITICAL"
        risk_color = "red"
    elif score >= 50:
        risk_level = "HIGH"
        risk_color = "orange"
    elif score >= 30:
        risk_level = "MEDIUM"
        risk_color = "yellow"
    else:
        risk_level = "LOW"
        risk_color = "green"
    
    return (min(score, 100), risk_level, risk_color, triggers)

# --- Raporlama ---
def generate_html_report(results, output_file):
    """
    Modern, interaktif HTML rapor oluşturur
    results: {'headers': {...}, 'urls': {...}, 'attachments': {...}, 'raw_headers': "..."}
    output_file: path to write report
    """
    from datetime import datetime, timezone
    import html as html_escape
    
    headers = results.get('headers', {})
    url_data = results.get('urls', {})
    attachments = results.get('attachments', {}).get('attachments', [])
    raw_headers = results.get('raw_headers', '')
    
    # Risk skoru hesapla
    risk_score, risk_level, risk_color, triggers = calculate_risk_score(headers)
    
    # Renk kodlarını belirle
    color_map = {
        'red': {'bg': 'rgba(239, 68, 68, 0.2)', 'text': '#ef4444', 'border': 'rgba(239, 68, 68, 0.3)', 'gradient': 'from-red-500 to-red-600'},
        'orange': {'bg': 'rgba(249, 115, 22, 0.2)', 'text': '#f97316', 'border': 'rgba(249, 115, 22, 0.3)', 'gradient': 'from-orange-500 to-orange-600'},
        'yellow': {'bg': 'rgba(234, 179, 8, 0.2)', 'text': '#eab308', 'border': 'rgba(234, 179, 8, 0.3)', 'gradient': 'from-yellow-500 to-yellow-600'},
        'green': {'bg': 'rgba(34, 197, 94, 0.2)', 'text': '#22c55e', 'border': 'rgba(34, 197, 94, 0.3)', 'gradient': 'from-green-500 to-green-600'}
    }
    colors = color_map.get(risk_color, color_map['green'])
    
    # Domain ve IP listelerini hazırla
    domains = list(set(url_data.get('domains', [])))
    all_ips = []
    if isinstance(headers.get('All Received IPs'), list):
        all_ips = headers.get('All Received IPs', [])
    elif isinstance(headers.get('Original IP'), str) and headers.get('Original IP') != 'Not Found':
        all_ips = [headers.get('Original IP')]
    
    # HTML başlangıcı
    html_content = f'''<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Phishing Analysis Report</title>
<link href="https://fonts.googleapis.com" rel="preconnect"/>
<link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght@400&display=swap" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = {{
    darkMode: "class",
    theme: {{
        extend: {{
            colors: {{
                "primary": "#13eca4",
                "background-dark": "#10221c",
                "card-dark": "#162b24",
                "border-dark": "#283933",
                "text-secondary": "#9db9b0"
            }},
            fontFamily: {{
                "display": ["Inter", "sans-serif"],
                "mono": ["JetBrains Mono", "monospace"],
            }}
        }}
    }}
}}
</script>
<style>
::-webkit-scrollbar {{ width: 8px; height: 8px; }}
::-webkit-scrollbar-track {{ background: #10221c; }}
::-webkit-scrollbar-thumb {{ background: #283933; border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: #3b544b; }}
</style>
</head>
<body class="bg-background-dark font-display text-white min-h-screen">
<main class="container mx-auto px-4 py-8 max-w-7xl">
<!-- Header -->
<div class="flex justify-between items-center mb-8 pb-4 border-b border-border-dark">
<div>
<h1 class="text-4xl font-black text-white mb-2">Phishing Analysis Report</h1>
</div>
<button onclick="window.print()" class="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 text-background-dark rounded-lg font-bold shadow-lg">
<span class="material-symbols-outlined">picture_as_pdf</span> Export PDF
</button>
</div>

<!-- Risk Score Card -->
<div class="bg-card-dark rounded-xl border border-border-dark p-6 mb-6">
<div class="flex items-center justify-between mb-4">
<h2 class="text-2xl font-bold text-white">Risk Score</h2>
<span class="px-4 py-2 rounded-full text-sm font-bold" style="background: {colors['bg']}; color: {colors['text']}; border: 1px solid {colors['border']}">{risk_level}</span>
</div>
<div class="flex items-end gap-4 mb-4">
<div>
<span class="text-6xl font-black text-white">{risk_score}</span>
<span class="text-text-secondary text-2xl">/100</span>
</div>
<div class="flex-1">
<div class="h-6 bg-background-dark rounded-full overflow-hidden border border-border-dark">
<div class="h-full bg-gradient-to-r {colors['gradient']} rounded-full" style="width: {risk_score}%"></div>
</div>
</div>
</div>
'''
    
    if triggers:
        html_content += '<div class="mt-4"><p class="text-sm font-bold text-text-secondary mb-2">Risk Triggers:</p><div class="flex flex-wrap gap-2">'
        for t in triggers:
            html_content += f'<span class="px-3 py-1 rounded text-xs font-mono" style="background: {colors["bg"]}; color: {colors["text"]}; border: 1px solid {colors["border"]}">{html_escape.escape(t)}</span>'
        html_content += '</div></div>'
    
    html_content += '</div>'
    
    html_content += '''
<!-- Email Metadata -->
<div class="bg-card-dark rounded-xl border border-border-dark p-6 mb-6">
<h2 class="text-xl font-bold text-white mb-4 border-b border-border-dark pb-2">Email Metadata</h2>
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
'''
    
    # Metadata alanları
    metadata_fields = ['Date', 'Subject', 'From', 'Reply-To', 'Return-Path', 'Original IP', 'All Received IPs' ,'SPF', 'DKIM', 'DMARC', 'ACTION']
    for field in metadata_fields:
        if field in headers:
            value = headers[field]
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value)
            html_content += f'''<div class="grid grid-cols-[120px_1fr] gap-2">
<span class="text-text-secondary text-sm">{field}:</span>
<span class="text-white text-sm font-mono break-all">{html_escape.escape(str(value))}</span>
</div>
'''
    
    html_content += '''</div>
</div>

<!-- Domains Section -->
'''
    
    if domains:
        html_content += f'''<div class="bg-card-dark rounded-xl border border-border-dark p-6 mb-6">
<h2 class="text-xl font-bold text-white mb-4 border-b border-border-dark pb-2">Detected Domains ({len(domains)})</h2>
<div class="space-y-3">
'''
        for domain in domains:
            domain_escaped = html_escape.escape(domain)
            html_content += f'''<div class="flex items-center justify-between p-3 bg-background-dark/50 rounded-lg border border-border-dark">
<div class="flex items-center gap-3">
<span class="material-symbols-outlined text-primary">language</span>
<span class="font-mono text-white">{domain_escaped}</span>
</div>
<div class="flex gap-2">
<a href="https://whois.com/whois/{domain_escaped}" target="_blank" class="px-3 py-1.5 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded text-blue-400 text-xs font-medium transition">WHOIS</a>
<a href="https://www.virustotal.com/gui/domain/{domain_escaped}" target="_blank" class="px-3 py-1.5 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded text-green-400 text-xs font-medium transition">VirusTotal</a>
</div>
</div>
'''
        html_content += '''</div>
</div>
'''
    
    # IP Addresses Section
    if all_ips:
        html_content += f'''<div class="bg-card-dark rounded-xl border border-border-dark p-6 mb-6">
<h2 class="text-xl font-bold text-white mb-4 border-b border-border-dark pb-2">IP Addresses ({len(all_ips)})</h2>
<div class="space-y-3">
'''
        for ip in all_ips:
            ip_escaped = html_escape.escape(str(ip))
            html_content += f'''<div class="flex items-center justify-between p-3 bg-background-dark/50 rounded-lg border border-border-dark">
<div class="flex items-center gap-3">
<span class="material-symbols-outlined text-purple-400">router</span>
<span class="font-mono text-white">{ip_escaped}</span>
</div>
<div class="flex gap-2">
<a href="https://www.abuseipdb.com/check/{ip_escaped}" target="_blank" class="px-3 py-1.5 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-500/30 rounded text-orange-400 text-xs font-medium transition">AbuseIPDB</a>
<a href="https://www.virustotal.com/gui/ip-address/{ip_escaped}" target="_blank" class="px-3 py-1.5 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded text-green-400 text-xs font-medium transition">VirusTotal</a>
</div>
</div>
'''
        html_content += '''</div>
</div>
'''
    
    # URLs Section
    url_list = url_data.get('urls', [])
    if url_list:
        html_content += f'''<div class="bg-card-dark rounded-xl border border-border-dark p-6 mb-6">
<h2 class="text-xl font-bold text-white mb-4 border-b border-border-dark pb-2">Detected URLs ({len(url_list)})</h2>
<div class="space-y-2">
'''
        for url in url_list[:50]:  # İlk 50 URL
            url_escaped = html_escape.escape(str(url))
            html_content += f'''<div class="p-2 bg-background-dark/50 rounded border border-border-dark">
<span class="font-mono text-sm text-primary break-all">{url_escaped}</span>
</div>
'''
        if len(url_list) > 50:
            html_content += f'<p class="text-text-secondary text-sm">... and {len(url_list) - 50} more URLs</p>'
        html_content += '''</div>
</div>
'''
    
    # Attachments Section
    if attachments:
        html_content += f'''<div class="bg-card-dark rounded-xl border border-border-dark p-6 mb-6">
<h2 class="text-xl font-bold text-white mb-4 border-b border-border-dark pb-2">Attachments ({len(attachments)})</h2>
<div class="space-y-4">
'''
        for att in attachments:
            filename_escaped = html_escape.escape(att['filename'])
            md5_escaped = html_escape.escape(att['md5'])
            sha256_escaped = html_escape.escape(att['sha256'])
            html_content += f'''<div class="p-4 bg-background-dark/50 rounded-lg border border-border-dark">
<div class="flex items-center justify-between mb-3">
<div class="flex items-center gap-2">
<span class="material-symbols-outlined text-red-400">attach_file</span>
<span class="font-medium text-white">{filename_escaped}</span>
</div>
<a href="https://www.virustotal.com/gui/file/{sha256_escaped}" target="_blank" class="px-3 py-1.5 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded text-green-400 text-xs font-medium transition">VirusTotal</a>
</div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
<div><span class="text-text-secondary">MD5:</span> <span class="font-mono text-white break-all">{md5_escaped}</span></div>
<div><span class="text-text-secondary">SHA256:</span> <span class="font-mono text-white break-all">{sha256_escaped}</span></div>
<div><span class="text-text-secondary">Size:</span> <span class="text-white">{att['size']} bytes</span></div>
</div>
</div>
'''
        html_content += '''</div>
</div>
'''
    
    # Raw Headers Section
    if raw_headers:
        raw_escaped = html_escape.escape(raw_headers)
        html_content += f'''<div class="bg-card-dark rounded-xl border border-border-dark p-6 mb-6">
<details class="group">
<summary class="cursor-pointer flex items-center justify-between p-2 hover:bg-background-dark/50 rounded">
<span class="text-xl font-bold text-white">Raw Email Headers</span>
<span class="material-symbols-outlined group-open:rotate-90 transition-transform">chevron_right</span>
</summary>
<div class="mt-4 p-4 bg-background-dark rounded border border-border-dark overflow-x-auto">
<pre class="font-mono text-xs text-text-secondary whitespace-pre-wrap break-words">{raw_escaped}</pre>
</div>
</details>
</div>
'''
    
    html_content += '''</main>
<footer class="text-center py-6 text-text-secondary text-xs">
Generated by Phishing Detector | Developed by wolkansec with vibe coding
</footer>
</body>
</html>'''
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)


# --- Ana Akış ---
import argparse

def main():
    parser = argparse.ArgumentParser(description="Phishing Detector: .eml phishing analysis tool. Developed by wolkansec with vibe coding.")
    parser.add_argument('-f', '--file', required=True, help='.eml file path')
    args = parser.parse_args()

    eml_path = args.file
    msg = parse_eml(eml_path)
    
    # Header analizi
    header_results = analyze_headers(msg)
    
    # URL/Domain analizi
    url_results = extract_urls(msg)
    from termcolor import cprint
    cprint("\n=== URL/DOMAIN ANALYSIS ===", "blue", attrs=["bold"])
    if url_results['urls']:
        defanged_urls = defang_indicators(url_results['urls'])
        print(colored(f"Number of URLs found: {len(url_results['urls'])}", "cyan"))
        for i, url in enumerate(defanged_urls, 1):
            print(colored(f"  {i}.", "cyan"), url)
        if url_results['domains']:
            print(colored(f"\nNumber of unique domains found: {len(url_results['domains'])}", "cyan"))
            for i, domain in enumerate(url_results['domains'], 1):
                print(colored(f"  {i}.", "cyan"), domain)
    else:
        print("No URL found.")
    
    # Ek analizi
    attachment_results = analyze_attachments(msg)
    cprint("\n=== ATTACHMENT ANALYSIS ===", "blue", attrs=["bold"])
    if attachment_results['attachments']:
        print(colored(f"Number of attachments found: {len(attachment_results['attachments'])}", "cyan"))
        for i, att in enumerate(attachment_results['attachments'], 1):
            print(colored(f"  Attachment {i}:", "cyan"), att['filename'])
            print(colored(f"    MD5:", "cyan"), att['md5'])
            print(colored(f"    SHA256:", "cyan"), att['sha256'])
            print(colored(f"    Size:", "cyan"), f"{att['size']} bytes")
    else:
        print("No attachments found.")
    
    # HTML raporu oluştur
    import os
    base_name = os.path.splitext(os.path.basename(eml_path))[0]
    report_name = f"{base_name}_report.html"
    results = {}
    results['headers'] = header_results
    results['urls'] = url_results
    results['attachments'] = attachment_results
    try:
        with open(eml_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_headers = f.read()
        results['raw_headers'] = raw_headers
    except Exception:
        results['raw_headers'] = ''
    generate_html_report(results, report_name)
    cprint(f"\n[+] HTML raporu otomatik kaydedildi: {report_name}", "green", attrs=["bold"])

if __name__ == "__main__":
    main()

