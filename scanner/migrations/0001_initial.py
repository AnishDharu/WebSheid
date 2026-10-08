# Generated manually for scanner models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ScannerPlugin',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('display_name', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('is_enabled', models.BooleanField(default=True)),
                ('version', models.CharField(default='1.0.0', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='ScanJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_url', models.URLField(max_length=500)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('running', 'Running'), ('completed', 'Completed'), ('failed', 'Failed')], default='pending', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('security_score', models.FloatField(blank=True, null=True)),
                ('risk_level', models.CharField(blank=True, max_length=20)),
                ('error_message', models.TextField(blank=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scans', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization', models.CharField(blank=True, max_length=200)),
                ('phone', models.CharField(blank=True, max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('total_scans', models.IntegerField(default=0)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ScanHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('raw_results', models.JSONField(default=dict)),
                ('summary', models.JSONField(default=dict)),
                ('ml_features', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('scan', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='history', to='scanner.scanjob')),
            ],
        ),
        migrations.CreateModel(
            name='ScanFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('plugin', models.CharField(choices=[('headers', 'Security Headers'), ('ssl', 'SSL/TLS'), ('dns', 'DNS/IP Analysis'), ('ports', 'Port Scanning'), ('xss', 'XSS Detection'), ('sqli', 'SQL Injection'), ('csrf', 'CSRF'), ('cookies', 'Cookie Security'), ('subdomains', 'Subdomain Discovery'), ('directories', 'Directory/Endpoint Exposure'), ('info', 'Website Information')], max_length=30)),
                ('title', models.CharField(max_length=300)),
                ('description', models.TextField()),
                ('severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical'), ('info', 'Info')], max_length=10)),
                ('impact', models.TextField(blank=True)),
                ('remediation', models.TextField(blank=True)),
                ('evidence', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='scanner.scanjob')),
            ],
            options={
                'ordering': ['-severity'],
            },
        ),
    ]
