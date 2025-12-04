import bleach

# given in spec
tags_allowed = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li', 'br']
attributes_allowed = {'a': ['href', 'title']}
protocols_allowed = ['http', 'https', 'mailto']

def sanitize_html(user_html: str) -> str:
    """Sanitize HTML using a whitelist and return safe HTML."""
    if not user_html:
        return ''
    cleaned = bleach.clean(user_html, tags=tags_allowed, attributes=attributes_allowed, protocols=protocols_allowed, strip=True)
    return cleaned