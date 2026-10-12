import subprocess

import pytest
from tartarus.errors import TartarusError
from tartarus.ludus import run_ludus


def test_sensitive_ludus_failure_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tartarus.ludus.shutil.which", lambda _: "/usr/bin/ludus")
    monkeypatch.setattr(
        "tartarus.ludus.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, stdout="PRIVATE-SECRET", stderr=""
        ),
    )
    with pytest.raises(TartarusError) as error:
        run_ludus(("users", "creds", "get"), sensitive=True)
    assert "PRIVATE-SECRET" not in str(error.value)
