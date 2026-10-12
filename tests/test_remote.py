from pathlib import Path

from tartarus.config import Config
from tartarus.ludus import CommandResult
from tartarus.remote import range_guests


def test_inventory_is_reduced_to_non_secret_guest_objects(tmp_path: Path, monkeypatch) -> None:
    inventory = """[WARNING]: Invalid characters were found in group names but not replaced, use
-vvvv to see details
all:
  children:
    T1:
      hosts:
        T1-elk-01: &host
          ansible_host: 192.0.2.10
          ludus_template_user: localuser
          ludus_template_password: secret
          proxmox_vmid: 101
        T1-remnux-01:
          <<: *host
          ansible_host: 192.0.2.20
          proxmox_vmid: 102
        T1-linux-sbx-01:
          <<: *host
          ansible_host: 192.0.2.30
          proxmox_vmid: 103
"""
    monkeypatch.setattr(
        "tartarus.remote.run_ludus",
        lambda *args, **kwargs: CommandResult(("ludus",), inventory, "", 0),
    )
    config = Config(
        evidence_root=tmp_path,
        cache_root=tmp_path,
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )
    guests = range_guests(config, "T1")
    assert guests["sandbox"].address == "192.0.2.30"
    assert guests["sandbox"].vmid == 103
