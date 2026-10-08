"""
Web Shield - Setup Script
Run this once to initialize the Django project.
"""
import os
import sys

def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'webshield.settings')

    import django
    django.setup()

    from django.core.management import call_command

    print("=" * 50)
    print("🛡️  Web Shield - Setup")
    print("=" * 50)

    print("\n[1/4] Creating database migrations...")
    call_command('makemigrations', 'scanner')

    print("\n[2/4] Applying migrations...")
    call_command('migrate')

    print("\n[3/4] Collecting static files...")
    call_command('collectstatic', '--noinput', verbosity=0)

    print("\n[4/4] Training ML model...")
    try:
        from scanner.ml_classifier import train_model
        success = train_model()
        if success:
            print("   ✅ ML model trained successfully!")
        else:
            print("   ⚠️  ML training skipped (scikit-learn may not be installed)")
    except Exception as e:
        print(f"   ⚠️  ML training error: {e}")

    print("\n" + "=" * 50)
    print("✅ Setup complete!")
    print("\nNext steps:")
    print("1. Create a superuser:  python manage.py createsuperuser")
    print("2. Start the server:    python manage.py runserver")
    print("3. Open browser:        http://127.0.0.1:8000")
    print("=" * 50)


if __name__ == '__main__':
    main()
