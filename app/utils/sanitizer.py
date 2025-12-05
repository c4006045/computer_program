import bleach

def sanitize_html(text: str) -> str:
    # given in spec
    tags_allowed = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li', 'br']
    attributes_allowed = {'a': ['href', 'title']}

    return bleach.clean(text or "", tags=tags_allowed, attributes=attributes_allowed, strip=True)