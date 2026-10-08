"""
Plugin Framework for Web Shield
Each plugin performs one independent security check.
"""
import socket
import ssl
import json
import re
import time
import urllib.parse
from datetime import datetime

try:
    import requests
    from requests.exceptions import RequestException, Timeout, ConnectionError
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def safe_request(url, timeout=10, verify=False, allow_redirects=True):
    """Make a safe HTTP request, returning None on failure."""
    if not REQUESTS_AVAILABLE:
        return None
    try:
        headers = {
            'User-Agent': 'WebShield-Scanner/1.0 (Security Assessment Tool)',
        }
        resp = requests.get(url, timeout=timeout, verify=verify,
                            allow_redirects=allow_redirects, headers=headers)
        return resp
    except Exception:
        return None


# ─────────────────────────────────────────────
# PLUGIN 1: Website & Server Information
# ─────────────────────────────────────────────
def plugin_website_info(url, parsed):
    findings = []
    raw = {}

    resp = safe_request(url)
    if resp is None:
        return findings, raw

    server = resp.headers.get('Server', '')
    powered_by = resp.headers.get('X-Powered-By', '')
    x_aspnet = resp.headers.get('X-AspNet-Version', '')
    raw['server'] = server
    raw['powered_by'] = powered_by
    raw['status_code'] = resp.status_code
    raw['response_time'] = resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0

    if server:
        findings.append({
            'title': f'Server Version Disclosed: {server}',
            'description': f'The web server is disclosing its software and version via the "Server" header: {server}. This information helps attackers fingerprint your infrastructure.',
            'severity': 'medium',
            'plugin': 'info',
            'impact': 'Attackers can identify known CVEs for the disclosed server version and target specific exploits.',
            'remediation': 'Configure your web server to suppress or generalize the Server header. For Apache: use ServerTokens Prod. For Nginx: use server_tokens off.',
            'evidence': f'Server: {server}',
        })

    if powered_by:
        findings.append({
            'title': f'X-Powered-By Header Disclosed: {powered_by}',
            'description': f'The application is disclosing its framework/platform via "X-Powered-By": {powered_by}',
            'severity': 'low',
            'plugin': 'info',
            'impact': 'Reveals backend technology stack, enabling targeted attacks.',
            'remediation': 'Remove or suppress the X-Powered-By header in your framework configuration.',
            'evidence': f'X-Powered-By: {powered_by}',
        })

    if x_aspnet:
        findings.append({
            'title': f'ASP.NET Version Disclosed: {x_aspnet}',
            'description': f'X-AspNet-Version header reveals the .NET runtime version: {x_aspnet}',
            'severity': 'low',
            'plugin': 'info',
            'impact': 'Exposes exact .NET version for targeted vulnerability exploitation.',
            'remediation': 'In Web.config, set <httpRuntime enableVersionHeader="false" />',
            'evidence': f'X-AspNet-Version: {x_aspnet}',
        })

    if not findings:
        findings.append({
            'title': 'Server Information Properly Hidden',
            'description': 'Server and technology headers are not exposing version information.',
            'severity': 'info',
            'plugin': 'info',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': 'No version disclosure detected.',
        })

    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 2: HTTP Security Headers
# ─────────────────────────────────────────────
def plugin_security_headers(url, parsed):
    findings = []
    raw = {}

    resp = safe_request(url)
    if resp is None:
        return findings, raw

    headers = resp.headers
    raw['headers'] = dict(headers)

    checks = [
        {
            'header': 'Strict-Transport-Security',
            'title': 'Missing HTTP Strict Transport Security (HSTS)',
            'description': 'HSTS header is missing. This allows attackers to perform SSL stripping attacks, downgrading HTTPS connections to HTTP.',
            'severity': 'high',
            'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        },
        {
            'header': 'Content-Security-Policy',
            'title': 'Missing Content Security Policy (CSP)',
            'description': 'CSP header is absent. Without CSP, the browser has no restrictions on what scripts can execute, enabling XSS attacks.',
            'severity': 'high',
            'remediation': "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'",
        },
        {
            'header': 'X-Frame-Options',
            'title': 'Missing X-Frame-Options (Clickjacking Protection)',
            'description': 'X-Frame-Options header is missing. The site can be embedded in an iframe, enabling clickjacking attacks.',
            'severity': 'medium',
            'remediation': 'Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN',
        },
        {
            'header': 'X-Content-Type-Options',
            'title': 'Missing X-Content-Type-Options',
            'description': 'Without nosniff directive, browsers may MIME-sniff responses, enabling content injection attacks.',
            'severity': 'medium',
            'remediation': 'Add: X-Content-Type-Options: nosniff',
        },
        {
            'header': 'Referrer-Policy',
            'title': 'Missing Referrer-Policy',
            'description': 'Without a Referrer-Policy, sensitive URL parameters may leak to third-party sites via the Referer header.',
            'severity': 'low',
            'remediation': 'Add: Referrer-Policy: no-referrer-when-downgrade or strict-origin-when-cross-origin',
        },
        {
            'header': 'Permissions-Policy',
            'title': 'Missing Permissions-Policy',
            'description': 'No Permissions-Policy header found. Browser features (camera, microphone, geolocation) are unrestricted.',
            'severity': 'low',
            'remediation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
        },
        {
            'header': 'X-XSS-Protection',
            'title': 'Missing X-XSS-Protection Header',
            'description': 'X-XSS-Protection is not set. While deprecated in modern browsers, older browsers rely on this for XSS filtering.',
            'severity': 'low',
            'remediation': 'Add: X-XSS-Protection: 1; mode=block',
        },
    ]

    missing_count = 0
    for check in checks:
        if check['header'] not in headers:
            missing_count += 1
            findings.append({
                'title': check['title'],
                'description': check['description'],
                'severity': check['severity'],
                'plugin': 'headers',
                'impact': f'Missing {check["header"]} header reduces the security posture of the application.',
                'remediation': check['remediation'],
                'evidence': f'Header "{check["header"]}" not present in HTTP response',
            })
        else:
            findings.append({
                'title': f'{check["header"]} Header Present',
                'description': f'Security header {check["header"]} is properly configured: {headers[check["header"]]}',
                'severity': 'info',
                'plugin': 'headers',
                'impact': 'N/A',
                'remediation': 'N/A',
                'evidence': f'{check["header"]}: {headers[check["header"]]}',
            })

    raw['missing_headers_count'] = missing_count
    raw['total_checks'] = len(checks)
    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 3: SSL/TLS Analysis
# ─────────────────────────────────────────────
def plugin_ssl_tls(url, parsed):
    findings = []
    raw = {}

    hostname = parsed.hostname
    port = parsed.port or 443

    if parsed.scheme != 'https':
        findings.append({
            'title': 'Site Not Using HTTPS',
            'description': 'The target URL is using HTTP instead of HTTPS. All data transmitted is unencrypted and visible to attackers.',
            'severity': 'critical',
            'plugin': 'ssl',
            'impact': 'All data including credentials, session tokens, and sensitive information is transmitted in plaintext.',
            'remediation': 'Obtain an SSL/TLS certificate (free via Let\'s Encrypt) and redirect all HTTP traffic to HTTPS.',
            'evidence': f'URL scheme: {parsed.scheme}',
        })
        raw['has_ssl'] = False
        return findings, raw

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(10)
        conn.connect((hostname, port))
        cert = conn.getpeercert()
        protocol = conn.version()
        cipher = conn.cipher()
        conn.close()

        raw['has_ssl'] = True
        raw['protocol'] = protocol
        raw['cipher'] = cipher[0] if cipher else 'Unknown'
        raw['cert'] = str(cert)

        # Check expiry
        expire_str = cert.get('notAfter', '')
        if expire_str:
            expire_dt = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_dt - datetime.utcnow()).days
            raw['cert_expiry_days'] = days_left

            if days_left < 0:
                findings.append({
                    'title': 'SSL Certificate Expired',
                    'description': f'The SSL certificate expired {abs(days_left)} days ago.',
                    'severity': 'critical',
                    'plugin': 'ssl',
                    'impact': 'Browsers will show security warnings; users cannot securely access the site.',
                    'remediation': 'Renew the SSL/TLS certificate immediately. Consider using Let\'s Encrypt for free auto-renewal.',
                    'evidence': f'Certificate expiry: {expire_str}',
                })
            elif days_left < 30:
                findings.append({
                    'title': f'SSL Certificate Expiring Soon ({days_left} days)',
                    'description': f'The SSL certificate will expire in {days_left} days.',
                    'severity': 'high',
                    'plugin': 'ssl',
                    'impact': 'Imminent certificate expiry will cause browser warnings and service disruption.',
                    'remediation': 'Renew the certificate before expiry. Set up auto-renewal using tools like Certbot.',
                    'evidence': f'Certificate expiry: {expire_str}',
                })
            else:
                findings.append({
                    'title': f'SSL Certificate Valid ({days_left} days remaining)',
                    'description': 'SSL certificate is valid and not near expiry.',
                    'severity': 'info',
                    'plugin': 'ssl',
                    'impact': 'N/A',
                    'remediation': 'N/A',
                    'evidence': f'Certificate expiry: {expire_str}',
                })

        # Check protocol version
        if protocol in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
            findings.append({
                'title': f'Outdated TLS Protocol: {protocol}',
                'description': f'The server supports {protocol} which is deprecated and vulnerable to known attacks (POODLE, BEAST, etc.).',
                'severity': 'high',
                'plugin': 'ssl',
                'impact': 'Encrypted connections can be broken using protocol downgrade attacks.',
                'remediation': 'Disable TLS 1.0 and 1.1. Only support TLS 1.2 and TLS 1.3.',
                'evidence': f'Negotiated protocol: {protocol}',
            })
        else:
            findings.append({
                'title': f'Modern TLS Protocol: {protocol}',
                'description': f'Server is using modern TLS protocol: {protocol}',
                'severity': 'info',
                'plugin': 'ssl',
                'impact': 'N/A',
                'remediation': 'N/A',
                'evidence': f'Negotiated protocol: {protocol}',
            })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            'title': 'Invalid SSL Certificate',
            'description': f'SSL certificate validation failed: {str(e)}',
            'severity': 'critical',
            'plugin': 'ssl',
            'impact': 'Users will see browser security warnings. Connections may be vulnerable to MITM attacks.',
            'remediation': 'Obtain a valid certificate from a trusted Certificate Authority.',
            'evidence': str(e),
        })
        raw['has_ssl'] = False
    except (socket.timeout, socket.error, ConnectionRefusedError) as e:
        findings.append({
            'title': 'Could Not Connect for SSL Check',
            'description': f'Failed to establish SSL connection: {str(e)}',
            'severity': 'medium',
            'plugin': 'ssl',
            'impact': 'SSL configuration could not be verified.',
            'remediation': 'Ensure SSL is properly configured on port 443.',
            'evidence': str(e),
        })
        raw['has_ssl'] = False
    except Exception as e:
        raw['ssl_error'] = str(e)
        raw['has_ssl'] = False

    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 4: DNS / IP Analysis
# ─────────────────────────────────────────────
def plugin_dns_ip(url, parsed):
    findings = []
    raw = {}

    hostname = parsed.hostname

    # IP Resolution
    try:
        ip = socket.gethostbyname(hostname)
        raw['resolved_ip'] = ip
        findings.append({
            'title': f'DNS Resolved: {hostname} → {ip}',
            'description': f'Successfully resolved hostname to IP address {ip}.',
            'severity': 'info',
            'plugin': 'dns',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': f'A record: {ip}',
        })
    except socket.gaierror as e:
        findings.append({
            'title': 'DNS Resolution Failed',
            'description': f'Could not resolve hostname: {hostname}. Error: {str(e)}',
            'severity': 'high',
            'plugin': 'dns',
            'impact': 'Site may be unreachable or using invalid DNS configuration.',
            'remediation': 'Verify DNS records are correctly configured for the domain.',
            'evidence': str(e),
        })
        return findings, raw

    if DNS_AVAILABLE:
        # SPF Record check
        try:
            spf_records = dns.resolver.resolve(hostname, 'TXT')
            has_spf = any('v=spf1' in str(r) for r in spf_records)
            raw['has_spf'] = has_spf
            if not has_spf:
                findings.append({
                    'title': 'Missing SPF DNS Record',
                    'description': 'No SPF (Sender Policy Framework) record found. This allows email spoofing from your domain.',
                    'severity': 'medium',
                    'plugin': 'dns',
                    'impact': 'Attackers can send phishing emails appearing to come from your domain.',
                    'remediation': 'Add a TXT record: v=spf1 include:_spf.google.com ~all (adjust for your mail provider)',
                    'evidence': 'No SPF TXT record found in DNS',
                })
            else:
                findings.append({
                    'title': 'SPF Record Present',
                    'description': 'SPF record found, helping prevent email spoofing.',
                    'severity': 'info',
                    'plugin': 'dns',
                    'impact': 'N/A',
                    'remediation': 'N/A',
                    'evidence': 'SPF TXT record detected',
                })
        except Exception:
            raw['has_spf'] = False

        # MX Records
        try:
            mx_records = dns.resolver.resolve(hostname, 'MX')
            raw['mx_records'] = [str(r) for r in mx_records]
        except Exception:
            raw['mx_records'] = []

        # DMARC check
        try:
            dmarc_host = f'_dmarc.{hostname}'
            dmarc_records = dns.resolver.resolve(dmarc_host, 'TXT')
            has_dmarc = any('v=DMARC1' in str(r) for r in dmarc_records)
            raw['has_dmarc'] = has_dmarc
            if not has_dmarc:
                findings.append({
                    'title': 'Missing DMARC Record',
                    'description': 'No DMARC policy found. Without DMARC, email authentication policies are not enforced.',
                    'severity': 'medium',
                    'plugin': 'dns',
                    'impact': 'Phishing emails from your domain may not be blocked by recipients.',
                    'remediation': 'Add a TXT record for _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
                    'evidence': 'No DMARC TXT record found',
                })
        except Exception:
            raw['has_dmarc'] = False

    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 5: Open Port Scanning
# ─────────────────────────────────────────────
def plugin_port_scan(url, parsed):
    findings = []
    raw = {}

    hostname = parsed.hostname

    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return findings, raw

    COMMON_PORTS = {
        21: ('FTP', 'high', 'FTP transmits data in cleartext including credentials. Exposed FTP is a common attack vector.'),
        22: ('SSH', 'info', 'SSH port is open. Ensure only key-based authentication is enabled.'),
        23: ('Telnet', 'critical', 'Telnet is completely unencrypted. Immediately disable Telnet and use SSH instead.'),
        25: ('SMTP', 'medium', 'SMTP port open. Ensure it is not an open relay and uses authentication.'),
        80: ('HTTP', 'info', 'HTTP port open. Ensure all traffic is redirected to HTTPS.'),
        443: ('HTTPS', 'info', 'HTTPS port open. Good for encrypted web traffic.'),
        3306: ('MySQL', 'critical', 'MySQL database port exposed to the internet. This is extremely dangerous.'),
        5432: ('PostgreSQL', 'critical', 'PostgreSQL port exposed to the internet. Immediately restrict access via firewall.'),
        6379: ('Redis', 'critical', 'Redis port exposed. Redis has no authentication by default — severe data breach risk.'),
        8080: ('HTTP-Alt', 'medium', 'Alternate HTTP port open. May expose admin panels or dev environments.'),
        8443: ('HTTPS-Alt', 'low', 'Alternate HTTPS port open. Verify this is intentional.'),
        27017: ('MongoDB', 'critical', 'MongoDB port exposed. Many MongoDB instances have been breached via open ports.'),
        3389: ('RDP', 'critical', 'RDP exposed to internet. High risk of brute force and ransomware attacks.'),
        5900: ('VNC', 'critical', 'VNC port open. Remote desktop access exposed with potential weak authentication.'),
    }

    open_ports = []
    for port, (service, severity, risk_desc) in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            open_ports.append(port)
            findings.append({
                'title': f'Open Port {port}/{service}',
                'description': f'Port {port} ({service}) is open and accessible.',
                'severity': severity,
                'plugin': 'ports',
                'impact': risk_desc,
                'remediation': f'Review whether port {port} needs to be publicly accessible. Use firewall rules to restrict access.',
                'evidence': f'Port {port} ({service}) responded to connection attempt',
            })

    raw['open_ports'] = open_ports
    raw['scanned_ports'] = list(COMMON_PORTS.keys())
    raw['target_ip'] = ip

    if not open_ports:
        findings.append({
            'title': 'No Risky Open Ports Detected',
            'description': 'None of the commonly exploited ports were found open.',
            'severity': 'info',
            'plugin': 'ports',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': f'Scanned ports: {list(COMMON_PORTS.keys())}',
        })

    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 6: Cookie Security
# ─────────────────────────────────────────────
def plugin_cookies(url, parsed):
    findings = []
    raw = {}

    resp = safe_request(url)
    if resp is None:
        return findings, raw

    cookies = resp.cookies
    raw['cookie_count'] = len(cookies)
    raw['cookies'] = []

    if not cookies:
        findings.append({
            'title': 'No Cookies Set',
            'description': 'No cookies were set in the response.',
            'severity': 'info',
            'plugin': 'cookies',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': 'No Set-Cookie headers found',
        })
        return findings, raw

    for cookie in cookies:
        cookie_info = {
            'name': cookie.name,
            'secure': cookie.secure,
            'httponly': 'HttpOnly' in str(cookie),
            'samesite': cookie._rest.get('SameSite', None) if hasattr(cookie, '_rest') else None,
        }
        raw['cookies'].append(cookie_info)

        if not cookie.secure and parsed.scheme == 'https':
            findings.append({
                'title': f'Cookie "{cookie.name}" Missing Secure Flag',
                'description': f'Cookie "{cookie.name}" does not have the Secure flag. It can be transmitted over unencrypted HTTP.',
                'severity': 'high',
                'plugin': 'cookies',
                'impact': 'Cookie can be intercepted by network attackers via HTTP connections.',
                'remediation': f'Set the Secure flag on cookie "{cookie.name}": Set-Cookie: {cookie.name}=value; Secure; HttpOnly; SameSite=Strict',
                'evidence': f'Set-Cookie: {cookie.name} (Secure flag absent)',
            })

        set_cookie_header = resp.headers.get('Set-Cookie', '')
        if 'HttpOnly' not in set_cookie_header and cookie.name in set_cookie_header:
            findings.append({
                'title': f'Cookie "{cookie.name}" Missing HttpOnly Flag',
                'description': f'Cookie "{cookie.name}" is accessible via JavaScript. This enables cookie theft via XSS attacks.',
                'severity': 'high',
                'plugin': 'cookies',
                'impact': 'XSS vulnerabilities can steal this cookie, leading to session hijacking.',
                'remediation': f'Add HttpOnly flag: Set-Cookie: {cookie.name}=value; HttpOnly; Secure; SameSite=Strict',
                'evidence': f'Set-Cookie: {cookie.name} (HttpOnly flag absent)',
            })

    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 7: XSS Detection (Passive/Reflective)
# ─────────────────────────────────────────────
def plugin_xss(url, parsed):
    findings = []
    raw = {}

    resp = safe_request(url)
    if resp is None:
        return findings, raw

    content = resp.text
    raw['content_length'] = len(content)

    # Check for inline scripts without nonces
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
    inline_event_handlers = re.findall(r'(on\w+\s*=\s*["\'][^"\']*["\'])', content, re.IGNORECASE)

    raw['inline_scripts_count'] = len(inline_scripts)
    raw['inline_event_handlers'] = len(inline_event_handlers)

    csp = resp.headers.get('Content-Security-Policy', '')

    if inline_scripts and not csp:
        findings.append({
            'title': 'Inline Scripts Without CSP Protection',
            'description': f'Found {len(inline_scripts)} inline <script> blocks with no Content-Security-Policy to restrict them. This enables XSS attacks.',
            'severity': 'high',
            'plugin': 'xss',
            'impact': 'Attackers who can inject content into the page can execute arbitrary JavaScript.',
            'remediation': "Implement CSP with nonces: Content-Security-Policy: script-src 'nonce-{random}'. Move all JS to external files.",
            'evidence': f'{len(inline_scripts)} inline script blocks detected without CSP',
        })

    if inline_event_handlers:
        findings.append({
            'title': f'Inline Event Handlers Detected ({len(inline_event_handlers)} instances)',
            'description': 'Inline event handlers (onclick, onmouseover, etc.) were found in the page source. These are a common vector for XSS.',
            'severity': 'medium',
            'plugin': 'xss',
            'impact': 'If user-controlled input reaches these handlers, JavaScript injection is possible.',
            'remediation': 'Move all event handlers to external JS files with addEventListener(). This also enables stricter CSP policies.',
            'evidence': f'{len(inline_event_handlers)} inline event handlers found',
        })

    # Check forms for XSS risk (no CSRF token + action URL)
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', content, re.IGNORECASE)
    raw['forms_count'] = len(forms)

    # Check if URL has parameters (reflection risk)
    if parsed.query:
        findings.append({
            'title': 'URL Parameters Present (Reflection Risk)',
            'description': 'URL contains query parameters that could be reflected in the page content. If not properly sanitized, these enable reflected XSS.',
            'severity': 'medium',
            'plugin': 'xss',
            'impact': 'Attacker can craft a URL with malicious script in parameters that executes in victim\'s browser.',
            'remediation': 'Sanitize all user input with html.escape() (Python) or equivalent. Implement output encoding.',
            'evidence': f'URL parameters: {parsed.query}',
        })

    if not findings:
        findings.append({
            'title': 'No Obvious XSS Indicators Found',
            'description': 'Passive XSS analysis did not detect obvious vulnerability indicators.',
            'severity': 'info',
            'plugin': 'xss',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': 'Passive scan completed with no flags',
        })

    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 8: SQL Injection (Passive)
# ─────────────────────────────────────────────
def plugin_sqli(url, parsed):
    findings = []
    raw = {}

    resp = safe_request(url)
    if resp is None:
        return findings, raw

    content = resp.text.lower()
    raw['has_query_params'] = bool(parsed.query)

    sql_error_signatures = [
        'sql syntax', 'mysql_fetch', 'ora-', 'unterminated quoted string',
        'pg_exec', 'sqlite_', 'sqlstate', 'microsoft ole db', 'odbc driver',
        'syntax error', 'division by zero', 'invalid query', 'error in your sql',
    ]

    found_errors = [sig for sig in sql_error_signatures if sig in content]
    raw['sql_error_signatures'] = found_errors

    if found_errors:
        findings.append({
            'title': 'SQL Error Messages Exposed in Page',
            'description': f'Raw SQL error messages are visible in the page response. This indicates poor error handling and likely SQL injection vulnerability.',
            'severity': 'critical',
            'plugin': 'sqli',
            'impact': 'Exposed SQL errors reveal database structure, table names, and query logic to attackers.',
            'remediation': 'Disable detailed error messages in production. Use parameterized queries/prepared statements.',
            'evidence': f'SQL error patterns found: {", ".join(found_errors)}',
        })

    if parsed.query and any(c in parsed.query for c in ["'", '"', '--', ';', '=']):
        findings.append({
            'title': 'Suspicious Characters in URL Parameters',
            'description': 'URL parameters contain characters commonly used in SQL injection attacks.',
            'severity': 'high',
            'plugin': 'sqli',
            'impact': 'If these parameters are used in database queries without parameterization, SQL injection is likely.',
            'remediation': 'Use parameterized queries or ORM. Never concatenate user input into SQL queries.',
            'evidence': f'Suspicious query string: {parsed.query}',
        })
    elif parsed.query:
        findings.append({
            'title': 'URL Contains Parameters (SQLi Risk Assessment)',
            'description': 'URL parameters detected. These endpoints should be tested against SQL injection.',
            'severity': 'medium',
            'plugin': 'sqli',
            'impact': 'If backend queries are not parameterized, these endpoints may be SQLi-vulnerable.',
            'remediation': 'Use ORM (like Django ORM) or parameterized queries for all database operations.',
            'evidence': f'Query parameters: {parsed.query}',
        })

    if not findings:
        findings.append({
            'title': 'No SQL Injection Indicators Detected',
            'description': 'No SQL error messages or obvious injection indicators found in response.',
            'severity': 'info',
            'plugin': 'sqli',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': 'Passive SQLi scan completed',
        })

    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 9: CSRF Analysis
# ─────────────────────────────────────────────
def plugin_csrf(url, parsed):
    findings = []
    raw = {}

    resp = safe_request(url)
    if resp is None:
        return findings, raw

    content = resp.text

    # Find all forms
    forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
    raw['form_count'] = len(forms)

    unprotected_forms = []
    for i, form in enumerate(forms):
        has_csrf_token = bool(re.search(
            r'(csrf|token|_token|__RequestVerificationToken)',
            form, re.IGNORECASE
        ))
        method = re.search(r'method\s*=\s*["\']?(get|post)["\']?', form, re.IGNORECASE)
        form_method = method.group(1).upper() if method else 'GET'

        if not has_csrf_token and form_method == 'POST':
            unprotected_forms.append(i + 1)

    raw['unprotected_forms'] = unprotected_forms

    if unprotected_forms:
        findings.append({
            'title': f'CSRF Protection Missing on {len(unprotected_forms)} Form(s)',
            'description': f'{len(unprotected_forms)} POST form(s) appear to lack CSRF tokens. Forms {unprotected_forms} are unprotected.',
            'severity': 'high',
            'plugin': 'csrf',
            'impact': 'Attackers can trick authenticated users into submitting malicious requests on their behalf.',
            'remediation': 'Add CSRF tokens to all state-changing forms. In Django, use {% csrf_token %} in every form.',
            'evidence': f'Forms without CSRF token: {unprotected_forms}',
        })

    if forms and not unprotected_forms:
        findings.append({
            'title': 'CSRF Tokens Present in Forms',
            'description': 'All detected forms appear to have CSRF protection tokens.',
            'severity': 'info',
            'plugin': 'csrf',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': f'{len(forms)} forms found, all appear to have CSRF tokens',
        })

    if not forms:
        findings.append({
            'title': 'No Forms Detected on Page',
            'description': 'No HTML forms found on the scanned page. CSRF analysis not applicable.',
            'severity': 'info',
            'plugin': 'csrf',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': 'No <form> tags found in page source',
        })

    return findings, raw


# ─────────────────────────────────────────────
# PLUGIN 10: Subdomain & Directory Discovery
# ─────────────────────────────────────────────
def plugin_subdomains_directories(url, parsed):
    findings = []
    raw = {}

    hostname = parsed.hostname
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Common subdomains to check
    common_subdomains = ['admin', 'api', 'dev', 'staging', 'test', 'mail', 'ftp', 'vpn', 'portal']
    found_subdomains = []

    for sub in common_subdomains:
        subdomain = f"{sub}.{hostname}"
        try:
            socket.gethostbyname(subdomain)
            found_subdomains.append(subdomain)
        except socket.gaierror:
            pass

    raw['found_subdomains'] = found_subdomains

    if found_subdomains:
        findings.append({
            'title': f'Active Subdomains Found: {len(found_subdomains)}',
            'description': f'Discovered {len(found_subdomains)} active subdomains: {", ".join(found_subdomains)}. Some may expose sensitive services.',
            'severity': 'medium',
            'plugin': 'subdomains',
            'impact': 'Staging/dev/admin subdomains may have weaker security posture than production.',
            'remediation': 'Audit all subdomains. Remove unused subdomains. Apply same security standards to all subdomains.',
            'evidence': f'Active subdomains: {", ".join(found_subdomains)}',
        })
    else:
        findings.append({
            'title': 'No Common Sensitive Subdomains Found',
            'description': 'No commonly-targeted subdomains (admin, dev, staging, api) were found active.',
            'severity': 'info',
            'plugin': 'subdomains',
            'impact': 'N/A',
            'remediation': 'N/A',
            'evidence': f'Checked: {", ".join(common_subdomains)}',
        })

    # Common sensitive directories/endpoints
    sensitive_paths = [
        '/admin', '/wp-admin', '/admin.php', '/.env', '/.git',
        '/config', '/backup', '/robots.txt', '/sitemap.xml',
        '/phpinfo.php', '/server-status', '/api/v1', '/swagger',
    ]
    exposed_paths = []

    for path in sensitive_paths:
        resp = safe_request(base_url + path, timeout=5)
        if resp and resp.status_code in [200, 301, 302, 403]:
            exposed_paths.append({'path': path, 'status': resp.status_code})

    raw['exposed_paths'] = exposed_paths

    for ep in exposed_paths:
        severity = 'critical' if ep['path'] in ['/.env', '/.git', '/phpinfo.php'] else \
                   'high' if ep['path'] in ['/admin', '/wp-admin', '/server-status'] else 'medium'
        findings.append({
            'title': f'Sensitive Path Accessible: {ep["path"]} (HTTP {ep["status"]})',
            'description': f'The path {ep["path"]} returned HTTP {ep["status"]}, indicating it may be accessible.',
            'severity': severity,
            'plugin': 'directories',
            'impact': f'Exposure of {ep["path"]} may reveal sensitive configuration, source code, or admin interfaces.',
            'remediation': f'Restrict access to {ep["path"]} using server configuration rules or remove it from production.',
            'evidence': f'GET {base_url}{ep["path"]} → HTTP {ep["status"]}',
        })

    return findings, raw


# ─────────────────────────────────────────────
# MASTER SCANNER ENGINE
# ─────────────────────────────────────────────
ALL_PLUGINS = [
    ('info',         'Website & Server Info',        plugin_website_info),
    ('headers',      'HTTP Security Headers',        plugin_security_headers),
    ('ssl',          'SSL/TLS Analysis',             plugin_ssl_tls),
    ('dns',          'DNS & IP Analysis',            plugin_dns_ip),
    ('ports',        'Port Scanning',                plugin_port_scan),
    ('cookies',      'Cookie Security',              plugin_cookies),
    ('xss',          'XSS Detection',                plugin_xss),
    ('sqli',         'SQL Injection',                plugin_sqli),
    ('csrf',         'CSRF Analysis',                plugin_csrf),
    ('subdomains',   'Subdomain & Directory Discovery', plugin_subdomains_directories),
]


def run_scan(target_url, progress_callback=None):
    """
    Run all plugins against target_url.
    Returns: (all_findings_list, raw_results_dict)
    """
    parsed = urllib.parse.urlparse(target_url)

    # Normalize URL
    if not parsed.scheme:
        target_url = 'https://' + target_url
        parsed = urllib.parse.urlparse(target_url)

    all_findings = []
    raw_results = {}

    for i, (plugin_key, plugin_name, plugin_func) in enumerate(ALL_PLUGINS):
        if progress_callback:
            progress_callback(plugin_key, plugin_name, i + 1, len(ALL_PLUGINS))
        try:
            findings, raw = plugin_func(target_url, parsed)
            for f in findings:
                f.setdefault('plugin', plugin_key)
            all_findings.extend(findings)
            raw_results[plugin_key] = raw
        except Exception as e:
            raw_results[plugin_key] = {'error': str(e)}
            all_findings.append({
                'title': f'{plugin_name} Plugin Error',
                'description': f'Error running {plugin_name} plugin: {str(e)}',
                'severity': 'info',
                'plugin': plugin_key,
                'impact': 'N/A',
                'remediation': 'N/A',
                'evidence': str(e),
            })

    return all_findings, raw_results
