"""
Forms for Web Shield scanner application
"""
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={
        'class': 'form-control',
        'placeholder': 'Email address',
        'id': 'id_email',
    }))
    first_name = forms.CharField(max_length=50, required=True, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'First name',
        'id': 'id_first_name',
    }))
    last_name = forms.CharField(max_length=50, required=True, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Last name',
        'id': 'id_last_name',
    }))
    organization = forms.CharField(max_length=200, required=False, widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Organization (optional)',
        'id': 'id_organization',
    }))

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Username',
                'id': 'id_username',
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Password',
            'id': 'id_password1',
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm password',
            'id': 'id_password2',
        })

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        if commit:
            user.save()
            UserProfile.objects.create(
                user=user,
                organization=self.cleaned_data.get('organization', '')
            )
        return user


class ScanForm(forms.Form):
    target_url = forms.URLField(
        label='Target Website URL',
        widget=forms.URLInput(attrs={
            'class': 'form-control scan-input',
            'placeholder': 'https://example.com',
            'id': 'id_target_url',
        }),
        help_text='Enter the URL of a website you own or have permission to test.',
    )
    consent = forms.BooleanField(
        required=True,
        label='I confirm I have authorization to scan this website.',
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'id': 'id_consent',
        }),
    )
