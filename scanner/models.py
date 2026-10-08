"""
Models for Web Shield Vulnerability Scanner

Modules:
- UserProfile: Extended user information
- ScanJob: A scan request for a target URL
- ScanFinding: Individual vulnerability finding from a scan
- ScanHistory: Stored results for each completed scan
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    organization = models.CharField(max_length=200, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    total_scans = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.user.username}'s Profile"


class ScanJob(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    target_url = models.URLField(max_length=500)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    security_score = models.FloatField(null=True, blank=True)
    risk_level = models.CharField(max_length=20, blank=True)  # Low/Medium/High/Critical
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Scan [{self.id}] - {self.target_url} by {self.user.username}"

    def get_duration(self):
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return round(delta.total_seconds(), 2)
        return None


class ScanFinding(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
        ('info', 'Info'),
    ]

    PLUGIN_CHOICES = [
        ('headers', 'Security Headers'),
        ('ssl', 'SSL/TLS'),
        ('dns', 'DNS/IP Analysis'),
        ('ports', 'Port Scanning'),
        ('xss', 'XSS Detection'),
        ('sqli', 'SQL Injection'),
        ('csrf', 'CSRF'),
        ('cookies', 'Cookie Security'),
        ('subdomains', 'Subdomain Discovery'),
        ('directories', 'Directory/Endpoint Exposure'),
        ('info', 'Website Information'),
    ]

    scan = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='findings')
    plugin = models.CharField(max_length=30, choices=PLUGIN_CHOICES)
    title = models.CharField(max_length=300)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    impact = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    evidence = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-severity']

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"

    def get_severity_color(self):
        colors = {
            'critical': '#ff2d55',
            'high': '#ff6b35',
            'medium': '#ffd60a',
            'low': '#30d158',
            'info': '#0a84ff',
        }
        return colors.get(self.severity, '#888')


class ScanHistory(models.Model):
    scan = models.OneToOneField(ScanJob, on_delete=models.CASCADE, related_name='history')
    raw_results = models.JSONField(default=dict)
    summary = models.JSONField(default=dict)
    ml_features = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"History for Scan [{self.scan.id}]"


class ScannerPlugin(models.Model):
    name = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=200)
    description = models.TextField()
    is_enabled = models.BooleanField(default=True)
    version = models.CharField(max_length=20, default='1.0.0')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.display_name} (v{self.version})"
