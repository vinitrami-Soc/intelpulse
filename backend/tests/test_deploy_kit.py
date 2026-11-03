"""The deploy kit (deploy/, docs/DEPLOY.md): what has to stay true of it between the CI job that runs
it on Docker (setup.sh, smoke.py, backup.sh, restore.sh against Postgres) and the next change."""
from __future__ import annotations

import importlib.util
import os
import stat
from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_engine

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
COMPOSE = yaml.safe_load((DEPLOY / "compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]


def test_the_app_is_published_on_the_machine_only():
    # CF-Connecting-IP is trusted as the client's address: only the tunnel may reach the app
    assert SERVICES["app"]["ports"] == ["127.0.0.1:${APP_PORT:-8000}:8000"]
    for name in ("db", "redis", "worker", "beat", "tunnel"):
        assert "ports" not in SERVICES[name], f"{name} publishes a port"


def test_the_app_containers_are_locked_down():
    for name in ("app", "worker", "beat"):
        service = SERVICES[name]
        assert service["read_only"] is True and service["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in service["security_opt"], name
        assert service["environment"]["ENVIRONMENT"] == "production", name


def test_the_worker_and_beat_are_not_judged_by_the_app_s_healthcheck():
    # the image's HEALTHCHECK asks port 8000, which only the app opens
    assert SERVICES["worker"]["healthcheck"] == {"disable": True}
    assert SERVICES["beat"]["healthcheck"] == {"disable": True}


def test_the_tunnel_starts_only_when_asked_for_and_waits_for_a_healthy_app():
    tunnel = SERVICES["tunnel"]
    assert tunnel["profiles"] == ["tunnel"]
    assert tunnel["depends_on"]["app"]["condition"] == "service_healthy"
    image, _, version = tunnel["image"].partition(":")
    assert image == "cloudflare/cloudflared" and version and version != "latest"


def test_every_image_is_pinned():
    for name, service in SERVICES.items():
        if "image" in service and "build" not in service:
            assert ":" in service["image"] and not service["image"].endswith(":latest"), name


@pytest.mark.parametrize("script", ["setup.sh", "update.sh", "backup.sh", "restore.sh", "smoke.py"])
def test_the_scripts_are_executable_and_strict(script):
    path = DEPLOY / script
    assert path.stat().st_mode & stat.S_IXUSR, f"{script} is not executable"
    if script.endswith(".sh"):
        assert "set -euo pipefail" in path.read_text(encoding="utf-8")


def test_setup_never_replaces_a_secret_it_wrote_before():
    text = (DEPLOY / "setup.sh").read_text(encoding="utf-8")
    assert 'if [ -f "$env_file" ]; then' in text and "keeping its secrets" in text
    assert 'chmod 600 "$env_file"' in text


def test_the_secrets_and_dumps_stay_out_of_git_and_the_image():
    assert "deploy/backups/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "deploy/" in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()


def test_the_worker_can_reach_its_redis_broker():
    # kombu 5.7 moved `packaging`, which its Redis transport imports, under the [redis] extra:
    # without it the worker and beat crash at start and the heartbeat never comes
    pins = (ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8")
    assert any(line.startswith("celery[redis]==") for line in pins.splitlines())


def test_the_smoke_test_needs_nothing_but_the_standard_library():
    spec = importlib.util.spec_from_file_location("smoke", DEPLOY / "smoke.py")
    source = (DEPLOY / "smoke.py").read_text(encoding="utf-8")
    imports = {line.split()[1].split(".")[0] for line in source.splitlines() if line.startswith(("import ", "from "))}
    assert imports <= {"__future__", "argparse", "json", "secrets", "sys", "time", "urllib", "typing"}, imports
    assert spec is not None


def test_the_sequence_resync_is_nothing_on_sqlite(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "m0009", ROOT / "backend" / "app" / "migrations" / "versions" / "0009_serial_sequences.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engine = create_engine(f"sqlite:///{tmp_path / 'x.db'}")
    with engine.begin() as conn:
        assert module.resync(conn) == []
    assert os.path.exists(tmp_path / "x.db")
