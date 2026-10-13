from pathlib import Path

import yaml


def test_all_blueprints_provision_with_egress_then_block_it_in_testing_mode() -> None:
    root = Path(__file__).parents[1]
    for path in (root / "blueprints").glob("*/range-config.yml"):
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert value["network"]["external_default"] == "ACCEPT"
        assert value["network"]["inter_vlan_default"] == "REJECT"
        assert value["network"]["wireguard_vlan_default"] == "REJECT"
        assert [vm["vlan"] for vm in value["ludus"]] == [10, 20, 30]
        assert all(vm["testing"]["block_internet"] is True for vm in value["ludus"])
        assert value["ludus"][0]["testing"]["snapshot"] is False
        assert all(vm["testing"]["snapshot"] is True for vm in value["ludus"][1:])
        rules = value["network"]["rules"]
        assert any(rule["vlan_src"] == 30 and rule["vlan_dst"] == 20 for rule in rules)
        assert not any(rule["vlan_src"] == 30 and rule["vlan_dst"] == "public" for rule in rules)
