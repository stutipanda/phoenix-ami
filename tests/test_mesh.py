import networkx as nx
import pytest

from src.mesh_sim import MeshNetwork, build_demo_mesh


def test_demo_mesh_has_alternate_route():
    mesh = build_demo_mesh()
    route = mesh.shortest_route("meter-A", "meter-D")
    assert route[0] == "meter-A"
    assert route[-1] == "meter-D"


def test_recovery_after_relay_failure():
    mesh = build_demo_mesh()
    result = mesh.simulate_relay_failure(
        "meter-A", "meter-D", "meter-B"
    )

    assert result.recovered
    assert result.route[0] == "meter-A"
    assert result.route[-1] == "meter-D"
    assert "meter-B" not in result.route
    assert result.elapsed_ms >= 0


def test_failure_without_alternate_route():
    mesh = MeshNetwork()
    mesh.add_meter("meter-A")
    mesh.add_meter("meter-B")
    mesh.add_meter("meter-C")
    mesh.add_link("meter-A", "meter-B")
    mesh.add_link("meter-B", "meter-C")

    result = mesh.simulate_relay_failure(
        "meter-A", "meter-C", "meter-B"
    )

    assert not result.recovered
    assert result.route == []


def test_invalid_latency_rejected():
    mesh = build_demo_mesh()
    with pytest.raises(ValueError):
        mesh.add_link("meter-A", "meter-D", latency_ms=0)
