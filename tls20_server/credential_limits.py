"""Shared local credential budgets, not TLS 2.0 protocol maxima.

The body budget includes the request context, list/entry length fields and
entry extensions. PKIX may append one separately configured trust anchor.
"""

MAX_CERTIFICATES = 64
MAX_CERT_DER = 65536
MAX_CERTIFICATE_BODY = 262144
