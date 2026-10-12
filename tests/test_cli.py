from types import SimpleNamespace

from tartarus.cli import (
    _is_new_template_build,
    _latest_template_builds,
    collect_strings,
    find_string,
)


def test_nested_ludus_json_helpers() -> None:
    value = {"result": [{"sourceID": "tartarus"}, {"range": {"rangeID": "Q1-3"}}]}
    assert find_string(value, {"rangeID"}) == "Q1-3"
    assert collect_strings(value, {"sourceID"}) == {"tartarus"}


def test_latest_template_builds_uses_newest_record(monkeypatch) -> None:
    history = [
        {
            "id": "new",
            "template": "tartarus-debian-12-template",
            "status": "running",
            "created": "2026-10-10T05:00:00Z",
        },
        {
            "id": "old",
            "template": "tartarus-debian-12-template",
            "status": "failure",
            "created": "2026-10-10T04:00:00Z",
        },
    ]
    monkeypatch.setattr(
        "tartarus.cli.run_ludus",
        lambda *args, **kwargs: SimpleNamespace(stdout=__import__("json").dumps(history)),
    )
    config = SimpleNamespace(ludus_config=None)

    assert _latest_template_builds(config)["tartarus-debian-12-template"]["id"] == "new"


def test_template_build_must_have_a_new_history_identifier() -> None:
    previous = {"id": "old", "status": "success"}

    assert not _is_new_template_build(previous, {"id": "old", "status": "success"})
    assert _is_new_template_build(previous, {"id": "new", "status": "running"})
    assert not _is_new_template_build(previous, None)
