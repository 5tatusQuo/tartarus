from tartarus.artifacts import locked_artifacts


def test_all_artifacts_have_unique_names() -> None:
    artifacts = locked_artifacts()
    names = [item["filename"] for item in artifacts]
    assert len(names) == len(set(names))
    assert {
        "elasticsearch-9.5.5-amd64.deb",
        "ghidra_11.4.2_PUBLIC_20250826.zip",
        "arcompact-ARCompact.slaspec",
    } <= set(names)
    for item in artifacts:
        assert ("role" in item) != ("destination" in item)


def test_offline_lock_includes_owned_template_isos() -> None:
    names = {item["filename"] for item in locked_artifacts()}
    assert {
        "debian-12.15.0-amd64-netinst.iso",
        "ubuntu-20.04.1-legacy-server-amd64.iso",
    } <= names
