from django import template
from django.utils.safestring import mark_safe
from urllib.parse import urlencode

register = template.Library()

@register.filter
def country_flag(country_code):
    """Convert a country code to a flag emoji."""
    if not country_code:
        return ''
    
    # Convert country code to uppercase
    country_code = country_code.upper()
    
    # Convert each letter to a regional indicator symbol emoji
    # Each regional indicator is 127397 code points after its corresponding ASCII letter
    flag = ''
    for char in country_code:
        if 'A' <= char <= 'Z':
            flag += chr(ord(char) + 127397)
    
    return mark_safe(flag)

@register.simple_tag
def query_transform(request, **kwargs):
    """
    Returns the URL-encoded querystring for the current page,
    updating the params with the key/value pairs from kwargs.
    """
    updated = request.GET.copy()
    for key, value in kwargs.items():
        updated[key] = value
    return urlencode(updated)

@register.filter
def get_item(dictionary, key):
    """Get an item from a dictionary safely."""
    return dictionary.get(key)

@register.filter
def get_attribute(obj, attr):
    """Get an attribute of an object safely."""
    return getattr(obj, attr, '')

@register.filter
def abs_value(value):
    """Return the absolute value."""
    return abs(value)

@register.filter
def format_headers(headers_str):
    """Format request headers for better display."""
    if not headers_str:
        return ''
    
    try:
        # Split headers by newline and format each line
        lines = headers_str.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            if ':' in line:
                header, value = line.split(':', 1)
                formatted_lines.append(f"<strong>{header.strip()}:</strong> {value.strip()}")
            else:
                formatted_lines.append(line)
        
        return mark_safe('<br>'.join(formatted_lines))
    except Exception:
        return headers_str

@register.simple_tag
def url_replace(request, field, value):
    """
    Template tag to replace a parameter in the current request's GET query string
    Usage: {% url_replace request 'page' 3 %}
    """
    query_dict = request.GET.copy()
    query_dict[field] = value
    return query_dict.urlencode()