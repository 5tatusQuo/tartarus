from __future__ import annotations

import json

from .config import Config
from .errors import TartarusError
from .remote import Remote, range_guests


def operator_access(config: Config, range_id: str) -> dict[str, object]:
    """Return only credentials and connection data intended for an operator."""
    guests = range_guests(config, range_id)
    bootstrap_raw = Remote(config, guests["elk"]).run(
        ("cat", "/root/tartarus-bootstrap.json"), sudo=True, timeout=30
    ).stdout
    try:
        elastic_password = json.loads(bootstrap_raw)["elastic_password"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise TartarusError("ELK credential bootstrap is invalid") from exc
    if not isinstance(elastic_password, str) or not elastic_password:
        raise TartarusError("ELK interactive password is unavailable")

    controller_key = config.cache_root / "secrets" / "controller_ed25519"
    key_path = str(controller_key) if controller_key.is_file() else None
    return {
        "range_id": range_id,
        "kibana": {
            "url": f"http://{guests['elk'].address}:5601",
            "username": "elastic",
            "password": elastic_password,
        },
        "ssh": {
            "authentication": "controller SSH key" if key_path else "Ludus inventory",
            "private_key": key_path,
            "guests": {
                role: {"address": guest.address, "username": guest.user}
                for role, guest in sorted(guests.items())
            },
        },
    }
