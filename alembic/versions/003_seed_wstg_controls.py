"""seed_wstg_controls

Seeds verification_domains and security_controls with OWASP WSTG taxonomy.
Required for verification_records FK to resolve.

Revision ID: 003_seed_wstg
Revises: 002_enterprise
"""
from typing import Sequence, Union

from alembic import op

revision: str = "003_seed_wstg"
down_revision: Union[str, Sequence[str], None] = "002_enterprise"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DOMAINS = [
    ("CONF", "Configuration Management", "Security configuration and hardening controls"),
    ("IDNT", "Identity Management", "Identity and access management controls"),
    ("AUTH", "Authentication Testing", "Authentication mechanism controls"),
    ("ATHZ", "Authorization Testing", "Authorization and access control controls"),
    ("SESS", "Session Management", "Session management controls"),
    ("INPV", "Input Validation Testing", "Input validation and injection controls"),
    ("CRYP", "Cryptography", "Cryptographic implementation controls"),
    ("ERRH", "Error Handling", "Error handling and logging controls"),
    ("CLNT", "Client Side Testing", "Client-side security controls"),
    ("API", "API Security", "API security controls"),
]

CONTROLS = [
    ("WSTG-CONF-01", "CONF", "Secure HTTP Headers", "Verify secure HTTP response headers are configured"),
    ("WSTG-CONF-02", "CONF", "TLS/SSL Configuration", "Verify strong TLS/SSL configuration"),
    ("WSTG-IDNT-01", "IDNT", "Role-based Access Control", "Verify role-based access control is implemented"),
    ("WSTG-AUTH-01", "AUTH", "Authentication Bypass", "Test for authentication bypass vulnerabilities"),
    ("WSTG-ATHZ-01", "ATHZ", "Insecure Direct Object References", "Test for insecure direct object references"),
    ("WSTG-SESS-01", "SESS", "Session Management Schema", "Verify session management implementation"),
    ("WSTG-INPV-01", "INPV", "Injection (SQL, OS, etc.)", "Test for injection vulnerabilities"),
    ("WSTG-INPV-02", "INPV", "Cross-Site Scripting (XSS)", "Test for cross-site scripting vulnerabilities"),
    ("WSTG-CRYP-01", "CRYP", "Strong Cryptography", "Verify strong cryptographic algorithms are used"),
    ("WSTG-API-01", "API", "API Inventory and Authentication", "Verify API inventory and authentication controls"),
]


def upgrade() -> None:
    conn = op.get_bind()

    conn.execute(
        __import__("sqlalchemy").text(
            "INSERT INTO verification_domains (id, name, description) VALUES "
            + ", ".join(f"(:id{i}, :name{i}, :desc{i})" for i in range(len(DOMAINS)))
            + " ON CONFLICT (id) DO NOTHING"
        ),
        {k: v for i, (id_, name, desc) in enumerate(DOMAINS)
         for k, v in {f"id{i}": id_, f"name{i}": name, f"desc{i}": desc}.items()},
    )

    conn.execute(
        __import__("sqlalchemy").text(
            "INSERT INTO security_controls (id, domain_id, code, name, description) VALUES "
            + ", ".join(f"(:id{i}, :dom{i}, :code{i}, :name{i}, :desc{i})" for i in range(len(CONTROLS)))
            + " ON CONFLICT (id) DO NOTHING"
        ),
        {k: v for i, (code, dom, name, desc) in enumerate(CONTROLS)
         for k, v in {f"id{i}": code, f"dom{i}": dom, f"code{i}": code, f"name{i}": name, f"desc{i}": desc}.items()},
    )


def downgrade() -> None:
    conn = op.get_bind()
    import sqlalchemy as sa

    codes = [c[0] for c in CONTROLS]
    conn.execute(
        sa.text("DELETE FROM security_controls WHERE id = ANY(:codes)"),
        {"codes": codes},
    )
    domain_ids = [d[0] for d in DOMAINS]
    conn.execute(
        sa.text("DELETE FROM verification_domains WHERE id = ANY(:ids)"),
        {"ids": domain_ids},
    )
