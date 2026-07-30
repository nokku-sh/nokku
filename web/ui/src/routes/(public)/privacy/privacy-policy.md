This Privacy Policy explains how Nokku ("we", "us", or "our") collects, uses, and protects your personal data when you use our service. We are committed to processing your data in compliance with the General Data Protection Regulation (GDPR).

**1. Data Controller**
[Name]
[Your Street Address, Optional but recommended]  
[Postal Code], Austria  
Email: [support@mizuchi.dev](mailto:support@mizuchi.dev)

**2. Data We Collect and Why**

We practice data minimization and only collect data strictly necessary to provide our Service securely.

- **Account Data:** When you register, we collect your name, username, email address, and an encrypted password hash (if applicable).
  - _Purpose:_ To create and manage your account, authenticate you, and communicate service updates.
  - _Legal Basis:_ Performance of a contract (Art. 6(1)(b) GDPR).
- **Audit Logs and Security Data:** Our control plane generates audit logs to track system access and modifications. These logs capture: `ip_address`, `user_agent`, `workspace_id`, `actor_id`, `action`, `auth_method`, and `resource_id`.
  - _Purpose:_ To provide the core security functionality of Nokku, allow you to audit your infrastructure, and prevent malicious activity.
  - _Legal Basis:_ Legitimate interests in ensuring network and information security (Art. 6(1)(f) GDPR) and performance of a contract (Art. 6(1)(b) GDPR).
- **System Errors & Telemetry:** We collect anonymized or pseudonymized operational data (e.g., Hostname, OS Type, Architecture) when errors occur to debug and improve the system.

**3. Use of Cookies**
We use only **Strictly Necessary Cookies** (session cookies) required for user authentication and security. We do not use tracking or marketing cookies. Therefore, no cookie consent banner is required. If we implement analytics in the future, we will use privacy-first, cookie-less solutions (e.g., Plausible).

**4. Third-Party Services (Sub-processors)**
To provide the Service, we utilize trusted third-party service providers located exclusively within the EU or utilizing EU data regions. We have Data Processing Agreements (DPAs) in place with these providers:

- **Hetzner (Germany):** Application hosting and infrastructure.
- **Aiven (EU Region):** Managed PostgreSQL database and backups.
- **Google Cloud (EU Region):** Key Management Service (KMS) for encrypting Root CAs.
- **Resend (EU):** Transactional email delivery (e.g., verification, passwordless logins).
- **Polar.sh:** Our Merchant of Record for processing payments and subscriptions.

**5. Data Retention**

- **Account Data:** Kept for the duration of your active subscription. If you delete your account, your personal data will be deleted within [e.g., 30 days], except for data required to be retained for tax/legal compliance.
- **Audit Logs:** Automatically deleted after one (1) year via a strict database Time-to-Live (TTL) policy.

**6. Your Rights Under GDPR**
As an EU resident, you have the right to:

- Access the personal data we hold about you.
- Request correction of inaccurate data.
- Request deletion of your data ("Right to be forgotten").
- Restrict or object to our processing of your data.
- Request data portability.

To exercise any of these rights, please contact us at [support@mizuchi.dev](mailto:support@mizuchi.dev). You also have the right to lodge a complaint with the Austrian Data Protection Authority (Datenschutzbehörde).
