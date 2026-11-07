"""newton_read must not run a Wi-Fi scan: the scan needs the owner's consent
(newton_plan_scan kind=wifi) and only summaries may reach the model.  The
router program still knows the verb, so validate_read accepts it for the
scan path; the refusal is at the tool boundary."""

import newton_mcp.server as server


def test_newton_read_refuses_wifiscan_before_any_device_contact(monkeypatch):
    def no_contact(self, *args, **kwargs):
        raise AssertionError("newton_read reached the device for a wifiscan")

    monkeypatch.setattr(server.NewtonService, "_ssh_read", no_contact)
    monkeypatch.setattr(server.NewtonService, "device_for", no_contact)
    monkeypatch.setattr(server.NewtonService, "__init__", lambda self: None)
    for command in ("wifiscan radio0", "wifiscan radio1", "  wifiscan   radio12 "):
        result = server.newton_read("lab-r1", command)
        assert "newton_plan_scan" in result["error"], result


def test_newton_read_description_does_not_offer_wifiscan():
    tool = server.mcp._tool_manager.get_tool("newton_read")
    assert "wifiscan" not in tool.description
