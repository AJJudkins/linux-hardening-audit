import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import hardening_audit as h


def put(root, path, text="", mode=0o644):
    p = root / path.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    os.chmod(p, mode)
    return p


@pytest.fixture
def good(tmp_path):
    put(tmp_path, "/etc/ssh/sshd_config", "PermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\nMaxAuthTries 3\n", 0o600)
    put(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
    put(tmp_path, "/etc/group")
    put(tmp_path, "/etc/shadow", "root:!:19000:0:99999:7:::\nalice:$6$hashhashhash:19000:0:99999:7:::\n", 0o640)
    put(tmp_path, "/etc/gshadow", "", 0o640)
    put(tmp_path, "/etc/sudoers", "", 0o440)
    put(tmp_path, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
    put(tmp_path, "/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";\n')
    put(tmp_path, "/proc/sys/kernel/randomize_va_space", "2\n")
    return tmp_path


def by(results, check):
    return next(r for r in results if r["check"] == check)


def test_good_system_has_no_fail_or_warn(good):
    res = h.Audit(str(good)).run()
    assert h.summarize(res)["FAIL"] == 0 and h.summarize(res)["WARN"] == 0
    assert h.exit_code(res) == 0 and h.exit_code(res, strict=True) == 0


def test_bad_ssh_flagged(good):
    put(good, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPermitEmptyPasswords yes\nPasswordAuthentication yes\nMaxAuthTries 10\n", 0o600)
    res = h.Audit(str(good)).run()
    assert by(res, "permitrootlogin")["status"] == "FAIL"
    assert by(res, "permitemptypasswords")["status"] == "FAIL"
    assert by(res, "passwordauthentication")["status"] == "WARN"
    assert by(res, "maxauthtries")["status"] == "WARN"
    assert h.exit_code(res) == 1


def test_first_occurrence_and_dropin_precedence(good):
    put(good, "/etc/ssh/sshd_config.d/10-local.conf", "PermitRootLogin no\n")
    put(good, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication no\n", 0o600)
    assert by(h.Audit(str(good)).run(), "permitrootlogin")["status"] == "PASS"


def test_ssh_defaults_reported_as_defaults(tmp_path):
    put(tmp_path, "/etc/ssh/sshd_config", "# nothing set\n", 0o600)
    r = by(h.Audit(str(tmp_path)).run(), "passwordauthentication")
    assert r["status"] == "WARN" and "default" in r["detail"]


def test_world_readable_shadow_and_writable_passwd_fail(good):
    os.chmod(good / "etc/shadow", 0o644)
    os.chmod(good / "etc/passwd", 0o666)
    res = h.Audit(str(good)).run()
    assert by(res, "/etc/shadow")["status"] == "FAIL" and "world-readable" in by(res, "/etc/shadow")["detail"]
    assert by(res, "/etc/passwd")["status"] == "FAIL"


def test_extra_uid0_and_empty_password(good):
    put(good, "/etc/passwd", "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/:/bin/sh\n")
    put(good, "/etc/shadow", "root:!:1:::::\nbob::1:::::\n", 0o640)
    res = h.Audit(str(good)).run()
    assert by(res, "uid0-accounts")["status"] == "FAIL" and "toor" in by(res, "uid0-accounts")["detail"]
    r = by(res, "empty-passwords")
    assert r["status"] == "FAIL" and "bob" in r["detail"]


def test_hashes_never_in_output(good):
    out = json.dumps(h.Audit(str(good)).run()) + h.format_report(h.Audit(str(good)).run())
    assert "hashhashhash" not in out


def test_firewall_variants(tmp_path):
    assert by(h.Audit(str(tmp_path)).run(), "host-firewall")["status"] == "WARN"
    put(tmp_path, "/etc/ufw/ufw.conf", "ENABLED=no\n")
    r = by(h.Audit(str(tmp_path)).run(), "host-firewall")
    assert r["status"] == "WARN" and "ufw" in r["detail"]
    put(tmp_path, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
    assert by(h.Audit(str(tmp_path)).run(), "host-firewall")["status"] == "PASS"


def test_updates_variants(tmp_path):
    assert by(h.Audit(str(tmp_path)).run(), "unattended-upgrades")["status"] == "WARN"
    put(tmp_path, "/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "0";\n')
    assert by(h.Audit(str(tmp_path)).run(), "unattended-upgrades")["status"] == "WARN"
    put(tmp_path, "/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";\n')
    assert by(h.Audit(str(tmp_path)).run(), "unattended-upgrades")["status"] == "PASS"


def test_aslr(tmp_path):
    put(tmp_path, "/proc/sys/kernel/randomize_va_space", "0\n")
    assert by(h.Audit(str(tmp_path)).run(), "aslr")["status"] == "FAIL"


def test_audit_never_modifies_the_tree(good):
    def snapshot():
        return {str(p): (p.stat().st_mode, p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
                for p in sorted(good.rglob("*"))}
    before = snapshot()
    h.Audit(str(good)).run()
    assert snapshot() == before


def test_cli(good, capsys, tmp_path):
    assert h.main(["--root", str(good)]) == 0
    assert "Linux hardening audit" in capsys.readouterr().out
    assert h.main(["--root", str(good), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["FAIL"] == 0
    assert h.main(["--root", str(tmp_path / "nope")]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert h.main(["--root", str(empty)]) == 0
    assert h.main(["--root", str(empty), "--strict"]) == 1  # empty tree => warnings => strict fails


def test_no_subprocess_or_network_imports():
    src = open(os.path.join(os.path.dirname(__file__), "..", "hardening_audit.py")).read()
    for banned in ("subprocess", "socket", "os.system", "shutil.rmtree", "os.chmod", "os.remove", "open(self.p(path), \"w"):
        assert banned not in src
