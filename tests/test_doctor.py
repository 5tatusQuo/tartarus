import pytest
from tartarus.doctor import _json_output, _version_tuple
from tartarus.errors import TartarusError


def test_json_output_ignores_human_prefix() -> None:
    assert _json_output('[INFO] client\n{"version":"2.3.7"}') == {"version": "2.3.7"}


def test_version_requires_semver() -> None:
    assert _version_tuple("Ludus Server 2.3.7+abc") == (2, 3, 7)
    with pytest.raises(TartarusError):
        _version_tuple("unknown")
