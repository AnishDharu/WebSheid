"""
Views for Web Shield Vulnerability Scanner
"""

import json
import threading
from datetime import datetime

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.db.models import Count, Avg, Q

from .models import ScanJob, ScanFinding, ScanHistory, UserProfile, ScannerPlugin
from .forms import RegisterForm, ScanForm
from .plugins import run_scan
from .ml_classifier import assess_risk, train_model
from .report_generator import generate_pdf_report


# ─────────────────────────────────────────────
# Helper: is_admin
# ─────────────────────────────────────────────
def is_admin(user):
    return user.is_staff or user.is_superuser


# ─────────────────────────────────────────────
# Landing / Home
# ─────────────────────────────────────────────
def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'scanner/home.html')


# ─────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────
def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f'Welcome to Web Shield, {user.first_name}! Your account is ready.')
            return redirect('dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = RegisterForm()
    return render(request, 'scanner/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f'Welcome back, {user.first_name or user.username}!')
            next_url = request.GET.get('next', 'dashboard')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = AuthenticationForm()
    return render(request, 'scanner/login.html', {'form': form})


def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('home')


# ─────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────
@login_required
def dashboard(request):
    user_scans = ScanJob.objects.filter(user=request.user).order_by('-created_at')
    recent_scans = user_scans[:5]
    total_scans = user_scans.count()
    completed_scans = user_scans.filter(status='completed').count()
    avg_score = user_scans.filter(status='completed').aggregate(Avg('security_score'))['security_score__avg']

    # Severity stats across all findings
    findings_qs = ScanFinding.objects.filter(scan__user=request.user)
    severity_counts = {
        'critical': findings_qs.filter(severity='critical').count(),
        'high': findings_qs.filter(severity='high').count(),
        'medium': findings_qs.filter(severity='medium').count(),
        'low': findings_qs.filter(severity='low').count(),
    }

    # Score trend for chart (last 7 scans)
    score_trend = list(
        user_scans.filter(status='completed').values('created_at', 'security_score', 'target_url')[:7]
    )

    # Risk distribution for chart
    risk_dist = {}
    for scan in user_scans.filter(status='completed'):
        rl = scan.risk_level or 'Unknown'
        risk_dist[rl] = risk_dist.get(rl, 0) + 1

    context = {
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'avg_score': round(avg_score, 1) if avg_score else None,
        'severity_counts': severity_counts,
        'score_trend': json.dumps(score_trend, default=str),
        'risk_dist': json.dumps(risk_dist),
    }
    return render(request, 'scanner/dashboard.html', context)


# ─────────────────────────────────────────────
# Scan Management
# ─────────────────────────────────────────────
@login_required
def new_scan(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            target_url = form.cleaned_data['target_url']
            scan = ScanJob.objects.create(
                user=request.user,
                target_url=target_url,
                status='pending',
            )
            # Run scan in background thread
            thread = threading.Thread(target=_run_scan_thread, args=(scan.id,), daemon=True)
            thread.start()
            messages.success(request, f'Scan #{scan.id} initiated for {target_url}. Processing...')
            return redirect('scan_status', scan_id=scan.id)
        else:
            messages.error(request, 'Please fix the form errors below.')
    else:
        form = ScanForm()
    return render(request, 'scanner/new_scan.html', {'form': form})


def _run_scan_thread(scan_id):
    """Background thread to run the full scan pipeline."""
    try:
        scan = ScanJob.objects.get(id=scan_id)
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.save()

        # Run all plugins
        all_findings, raw_results = run_scan(scan.target_url)

        # ML Risk Assessment
        score, risk_level, severity_summary, features = assess_risk(all_findings, raw_results)

        # Save findings to DB
        finding_objects = []
        for f in all_findings:
            finding_objects.append(ScanFinding(
                scan=scan,
                plugin=f.get('plugin', 'info'),
                title=f.get('title', '')[:300],
                description=f.get('description', ''),
                severity=f.get('severity', 'info'),
                impact=f.get('impact', ''),
                remediation=f.get('remediation', ''),
                evidence=f.get('evidence', ''),
            ))
        ScanFinding.objects.bulk_create(finding_objects)

        # Save history
        ScanHistory.objects.create(
            scan=scan,
            raw_results=raw_results,
            summary={'severity_summary': severity_summary},
            ml_features=features.tolist() if hasattr(features, 'tolist') else list(features),
        )

        # Update scan job
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.security_score = round(score, 2)
        scan.risk_level = risk_level
        scan.save()

        # Update user profile scan count
        try:
            profile = scan.user.profile
            profile.total_scans += 1
            profile.save()
        except Exception:
            pass

    except ScanJob.DoesNotExist:
        pass
    except Exception as e:
        try:
            scan = ScanJob.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.completed_at = timezone.now()
            scan.save()
        except Exception:
            pass


SECURITY_CHECKS = [
    ('🔒', 'HTTP Security Headers'),
    ('🔐', 'SSL/TLS Certificate & Cipher'),
    ('🌐', 'DNS & IP Infrastructure'),
    ('🚪', 'Open Port Scanning'),
    ('🍪', 'Cookie Security Flags'),
    ('💉', 'Cross-Site Scripting (XSS)'),
    ('🗄️', 'SQL Injection Detection'),
    ('🎭', 'CSRF Protection Analysis'),
    ('🔍', 'Subdomain & Directory Discovery'),
    ('📡', 'Server & Technology Information'),
]


@login_required
def scan_status(request, scan_id):
    scan = get_object_or_404(ScanJob, id=scan_id, user=request.user)
    return render(request, 'scanner/scan_status.html', {
        'scan': scan,
        'security_checks': SECURITY_CHECKS,
    })


@login_required
def scan_status_api(request, scan_id):
    """API endpoint for polling scan status."""
    scan = get_object_or_404(ScanJob, id=scan_id, user=request.user)
    return JsonResponse({
        'status': scan.status,
        'security_score': scan.security_score,
        'risk_level': scan.risk_level,
        'error_message': scan.error_message,
    })


@login_required
def scan_report(request, scan_id):
    scan = get_object_or_404(ScanJob, id=scan_id, user=request.user)
    if scan.status != 'completed':
        messages.warning(request, 'Scan is not yet complete.')
        return redirect('scan_status', scan_id=scan.id)

    findings = scan.findings.all().order_by('severity')

    # Group findings by severity
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    grouped = {s: list(findings.filter(severity=s)) for s in severity_order}

    severity_counts = {s: len(v) for s, v in grouped.items()}

    # Group by plugin
    plugin_groups = {}
    for f in findings:
        plugin = f.get_plugin_display()
        if plugin not in plugin_groups:
            plugin_groups[plugin] = []
        plugin_groups[plugin].append(f)

    # Chart data
    chart_labels = [s.capitalize() for s in severity_order if severity_counts.get(s, 0) > 0]
    chart_values = [severity_counts.get(s, 0) for s in severity_order if severity_counts.get(s, 0) > 0]

    context = {
        'scan': scan,
        'findings': findings,
        'grouped': grouped,
        'severity_counts': severity_counts,
        'plugin_groups': plugin_groups,
        'chart_labels': json.dumps(chart_labels),
        'chart_values': json.dumps(chart_values),
        'total_issues': findings.exclude(severity='info').count(),
    }
    return render(request, 'scanner/scan_report.html', context)


@login_required
def download_report(request, scan_id):
    scan = get_object_or_404(ScanJob, id=scan_id, user=request.user)
    if scan.status != 'completed':
        messages.warning(request, 'Scan is not complete yet.')
        return redirect('scan_status', scan_id=scan.id)

    findings_qs = scan.findings.all()
    findings_list = [{
        'title': f.title,
        'description': f.description,
        'severity': f.severity,
        'impact': f.impact,
        'remediation': f.remediation,
        'evidence': f.evidence,
        'plugin': f.plugin,
    } for f in findings_qs]

    try:
        history = scan.history
        summary = history.summary
    except Exception:
        summary = {}

    try:
        pdf_bytes = generate_pdf_report(scan, findings_list, summary)
    except Exception as e:
        messages.error(request, f'Unable to generate report: {e}')
        return redirect('scan_report', scan_id=scan.id)

    import re
    safe_target = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', scan.target_url.replace('https://', '').replace('http://', ''))[:40]
    filename = f"webshield_report_{scan.id}_{safe_target}.pdf"

    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    response['Content-Length'] = len(pdf_bytes)
    return response


# ─────────────────────────────────────────────
# Scan History
# ─────────────────────────────────────────────
@login_required
def scan_history(request):
    scans = ScanJob.objects.filter(user=request.user).order_by('-created_at')

    # Filter
    status_filter = request.GET.get('status', '')
    url_filter = request.GET.get('url', '')
    if status_filter:
        scans = scans.filter(status=status_filter)
    if url_filter:
        scans = scans.filter(target_url__icontains=url_filter)

    context = {
        'scans': scans,
        'status_filter': status_filter,
        'url_filter': url_filter,
    }
    return render(request, 'scanner/scan_history.html', context)


@login_required
def delete_scan(request, scan_id):
    scan = get_object_or_404(ScanJob, id=scan_id, user=request.user)
    if request.method == 'POST':
        scan.delete()
        messages.success(request, f'Scan #{scan_id} deleted.')
    return redirect('scan_history')


# ─────────────────────────────────────────────
# Admin Panel
# ─────────────────────────────────────────────
@login_required
@user_passes_test(is_admin)
def admin_panel(request):
    total_users = User.objects.count()
    total_scans = ScanJob.objects.count()
    completed_scans = ScanJob.objects.filter(status='completed').count()
    failed_scans = ScanJob.objects.filter(status='failed').count()
    recent_scans = ScanJob.objects.select_related('user').order_by('-created_at')[:10]
    all_users = User.objects.all().order_by('-date_joined')
    plugins = ScannerPlugin.objects.all()

    # Plugin health - ensure default plugins exist
    _ensure_default_plugins()
    plugins = ScannerPlugin.objects.all()

    context = {
        'total_users': total_users,
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'recent_scans': recent_scans,
        'all_users': all_users,
        'plugins': plugins,
    }
    return render(request, 'scanner/admin_panel.html', context)


@login_required
@user_passes_test(is_admin)
def toggle_plugin(request, plugin_id):
    plugin = get_object_or_404(ScannerPlugin, id=plugin_id)
    plugin.is_enabled = not plugin.is_enabled
    plugin.save()
    status = 'enabled' if plugin.is_enabled else 'disabled'
    messages.success(request, f'Plugin "{plugin.display_name}" {status}.')
    return redirect('admin_panel')


@login_required
@user_passes_test(is_admin)
def admin_delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST' and user != request.user:
        user.delete()
        messages.success(request, f'User {user.username} deleted.')
    return redirect('admin_panel')


@login_required
@user_passes_test(is_admin)
def train_ml_model(request):
    if request.method == 'POST':
        success = train_model()
        if success:
            messages.success(request, 'ML model trained and saved successfully!')
        else:
            messages.error(request, 'ML training failed. scikit-learn may not be installed.')
    return redirect('admin_panel')


def _ensure_default_plugins():
    """Create default plugin records if they don't exist."""
    default_plugins = [
        ('info', 'Website & Server Info', 'Collects server version, response codes, and technology disclosure.'),
        ('headers', 'HTTP Security Headers', 'Checks for missing security headers like CSP, HSTS, X-Frame-Options.'),
        ('ssl', 'SSL/TLS Analysis', 'Validates certificate, protocol version, and cipher strength.'),
        ('dns', 'DNS & IP Analysis', 'Checks DNS records, SPF, DMARC, and resolves IP addresses.'),
        ('ports', 'Port Scanner', 'Scans for open dangerous ports like MySQL, Redis, RDP, VNC.'),
        ('cookies', 'Cookie Security', 'Checks for Secure, HttpOnly, and SameSite cookie flags.'),
        ('xss', 'XSS Detection', 'Passively detects inline scripts, event handlers, and reflection risks.'),
        ('sqli', 'SQL Injection Detection', 'Checks for SQL error messages and suspicious URL parameters.'),
        ('csrf', 'CSRF Analysis', 'Checks forms for CSRF token protection.'),
        ('subdomains', 'Subdomain & Directory Discovery', 'Discovers active subdomains and exposed sensitive paths.'),
    ]
    for name, display_name, description in default_plugins:
        ScannerPlugin.objects.get_or_create(
            name=name,
            defaults={'display_name': display_name, 'description': description}
        )
