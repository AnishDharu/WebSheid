"""
Custom template tags and filters for Web Shield
"""
from django import template

register = template.Library()


@register.filter
def dict_item(d, key):
    """Get item from dictionary by key in templates."""
    if isinstance(d, dict):
        return d.get(key, [])
    return []


@register.filter
def split(value, delimiter=','):
    """Split a string by delimiter."""
    return value.split(delimiter)


@register.filter
def widthratio_custom(value, max_value):
    """Calculate percentage for width ratios."""
    try:
        return int((int(value) / int(max_value)) * 100)
    except (ValueError, ZeroDivisionError):
        return 0
