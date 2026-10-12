# Security policy

Do not report vulnerabilities with live malware, credentials, private keys, evidence, operator addresses, or infrastructure exports attached. Provide a minimal benign reproducer and redact diagnostic output.

Tartarus is not a security boundary until the complete live acceptance suite passes on the target deployment. Keep the Ludus and Proxmox APIs off the public internet, preserve deny-by-default router policy, and use only legally authorized samples.

Generated TLS keys, API keys, passwords, WireGuard material, samples, and evidence must remain outside Git. If any secret is exposed, revoke it at the issuing service; deleting it from the working tree is not sufficient.
