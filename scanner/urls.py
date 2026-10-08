"""
URL configuration for the scanner app
"""
from django.urls import path
from . import views

urlpatterns = [
    # Landing
    path('', views.home, name='home'),

    # Auth
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),

    # Scanning
    path('scan/new/', views.new_scan, name='new_scan'),
    path('scan/<int:scan_id>/status/', views.scan_status, name='scan_status'),
    path('scan/<int:scan_id>/status/api/', views.scan_status_api, name='scan_status_api'),
    path('scan/<int:scan_id>/report/', views.scan_report, name='scan_report'),
    path('scan/<int:scan_id>/download/', views.download_report, name='download_report'),
    path('scan/<int:scan_id>/delete/', views.delete_scan, name='delete_scan'),

    # History
    path('history/', views.scan_history, name='scan_history'),

    # Admin
    path('admin-panel/', views.admin_panel, name='admin_panel'),
    path('admin-panel/plugin/<int:plugin_id>/toggle/', views.toggle_plugin, name='toggle_plugin'),
    path('admin-panel/user/<int:user_id>/delete/', views.admin_delete_user, name='admin_delete_user'),
    path('admin-panel/train-ml/', views.train_ml_model, name='train_ml_model'),
]
