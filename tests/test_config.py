from pathlib import Path

import pytest
from tartarus.config import Config, load_config, save_config
from tartarus.errors import TartarusError


def test_config_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    expected = Config(
        evidence_root=tmp_path / "evidence",
        cache_root=tmp_path / "cache",
        management_sources=("198.51.100.2/32",),
        always_blocked_networks=("192.0.2.0/24",),
        host_memory_gib=16,
    )
    save_config(expected, path)
    assert load_config(path) == expected
    assert path.stat().st_mode & 0o777 == 0o600


def test_config_rejects_host_bits(tmp_path: Path) -> None:
    config = Config(
        evidence_root=tmp_path,
        management_sources=("198.51.100.2/24",),
        always_blocked_networks=("192.0.2.0/24",),
    )
    with pytest.raises(TartarusError, match="invalid CIDR"):
        config.validate()


def test_config_rejects_management_block_overlap(tmp_path: Path) -> None:
    config = Config(
        evidence_root=tmp_path,
        management_sources=("192.0.2.4/32",),
        always_blocked_networks=("192.0.2.0/24",),
    )
    with pytest.raises(TartarusError, match="must not overlap"):
        config.validate()
