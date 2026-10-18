"""Read-only Linux hardening audit: prints a pass / warn / fail report.

It only READS local files (config files, file modes, /proc/sys). It never
modifies the system, never runs external commands, never opens the network,
and never prints password hashes. Remediation hints are printed as text only.

Exit codes: 0 no FAIL (and no WARN with --strict), 1 at least one FAIL
(or WARN with --strict), 2 usage error.
"""
import argparse
import glob
import json
import os
import stat
import sys

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"


class Audit:
    """Audits a filesystem rooted at `root` ("/" for the real system)."""

    def __init__(self, root="/"):
        self.root = root
        self.results = []

    # ---- helpers (all read-only)
    def p(self, path):
        return os.path.join(self.root, path.lstrip("/"))

    def read(self, path):
        try:
            with open(self.p(path), errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def add(self, area, check, status, detail, hint=""):
        self.results.append({"area": area, "check": check, "status": status, "detail": detail, "hint": hint})

    # ---- SSH
    def sshd_config(self):
        """Effective-ish sshd settings: first occurrence wins, includes in sshd_config.d read first."""
        files = sorted(glob.glob(self.p("/etc/ssh/sshd_config.d/*.conf")))
        texts = [t for t in (self.read(os.path.relpath(f, self.root)) for f in files) if t is not None]
        main = self.read("/etc/ssh/sshd_config")
        if main is None and not texts:
            return None
        # sshd_config normally begins with `Include sshd_config.d/*.conf`, so drop-ins win when present.
        texts += [main or ""]
        settings = {}
        for text in texts:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].lower() not in settings:
                    settings[parts[0].lower()] = parts[1].strip().strip('"').lower()
        return settings

    def check_ssh(self):
        s = self.sshd_config()
        if s is None:
            self.add("ssh", "sshd_config", SKIP, "no sshd_config found or readable (sshd not installed?)")
            return
        rules = [
            # key, default, pass-values, fail-values, hint
            ("permitrootlogin", "prohibit-password", {"no", "prohibit-password", "without-password", "forced-commands-only"},
             {"yes"}, "Set 'PermitRootLogin no' in sshd_config."),
            ("passwordauthentication", "yes", {"no"}, set(), "Use keys and set 'PasswordAuthentication no'."),
            ("permitemptypasswords", "no", {"no"}, {"yes"}, "Set 'PermitEmptyPasswords no'."),
            ("x11forwarding", "no", {"no"}, set(), "Set 'X11Forwarding no' unless needed."),
        ]
        for key, default, ok, bad, hint in rules:
            val, explicit = s.get(key, default), key in s
            status = PASS if val in ok else FAIL if val in bad else WARN
            self.add("ssh", key, status, f"{key}={val}" + ("" if explicit else " (OpenSSH default)"), "" if status == PASS else hint)
        tries = s.get("maxauthtries", "6")
        try:
            status = PASS if int(tries) <= 4 else WARN
        except ValueError:
            status = WARN
        self.add("ssh", "maxauthtries", status, f"maxauthtries={tries}" + ("" if "maxauthtries" in s else " (OpenSSH default)"),
                 "" if status == PASS else "Set 'MaxAuthTries 4' or lower.")

    # ---- file permissions
    def check_file_modes(self):
        # path, max allowed mode, severity if exceeded, world-readable forbidden
        items = [("/etc/passwd", 0o644, WARN), ("/etc/group", 0o644, WARN),
                 ("/etc/shadow", 0o640, FAIL), ("/etc/gshadow", 0o640, FAIL),
                 ("/etc/ssh/sshd_config", 0o644, WARN), ("/etc/sudoers", 0o440, WARN)]
        real = os.path.realpath(self.root) == "/"
        for path, max_mode, sev in items:
            try:
                st = os.stat(self.p(path))
            except OSError:
                self.add("files", path, SKIP, "not present / not readable")
                continue
            mode = stat.S_IMODE(st.st_mode)
            problems = []
            if mode & stat.S_IWOTH:
                problems.append("world-writable")
            if mode & ~max_mode:
                problems.append(f"mode {mode:04o} is more permissive than {max_mode:04o}")
            if path in ("/etc/shadow", "/etc/gshadow") and mode & stat.S_IROTH:
                problems.append("world-readable")
            if real and st.st_uid != 0:
                problems.append(f"owned by uid {st.st_uid}, not root")
            if problems:
                world_w = mode & stat.S_IWOTH or (path in ("/etc/shadow", "/etc/gshadow") and mode & stat.S_IROTH)
                self.add("files", path, FAIL if (world_w or sev == FAIL) else WARN, "; ".join(problems),
                         f"chmod {max_mode:04o} {path}  # (hint only, not executed)")
            else:
                self.add("files", path, PASS, f"mode {mode:04o}")

    # ---- accounts
    def check_accounts(self):
        passwd = self.read("/etc/passwd")
        if passwd is not None:
            extra = [l.split(":")[0] for l in passwd.splitlines()
                     if l.count(":") >= 3 and l.split(":")[2] == "0" and l.split(":")[0] != "root"]
            self.add("accounts", "uid0-accounts", FAIL if extra else PASS,
                     f"extra UID 0 accounts: {', '.join(extra)}" if extra else "only root has UID 0",
                     "Investigate and remove extra UID 0 accounts." if extra else "")
        shadow = self.read("/etc/shadow")
        if shadow is None:
            self.add("accounts", "empty-passwords", SKIP, "/etc/shadow not readable (run as root to check)")
        else:
            empty = [l.split(":")[0] for l in shadow.splitlines() if l.count(":") >= 2 and l.split(":")[1] == ""]
            self.add("accounts", "empty-passwords", FAIL if empty else PASS,
                     f"accounts with empty password field: {', '.join(empty)}" if empty else "no empty password fields",
                     "Lock or set passwords for these accounts." if empty else "")

    # ---- firewall
    def check_firewall(self):
        found = []
        ufw = self.read("/etc/ufw/ufw.conf")
        if ufw is not None:
            enabled = any(l.strip().lower() == "enabled=yes" for l in ufw.splitlines())
            found.append(("ufw", enabled))
        if os.path.exists(self.p("/usr/sbin/firewalld")) or os.path.exists(self.p("/etc/firewalld")):
            found.append(("firewalld", os.path.exists(self.p("/run/firewalld.pid")) or os.path.exists(self.p("/run/firewalld"))))
        nft = self.read("/etc/nftables.conf")
        if nft is not None:
            found.append(("nftables", any(l.strip() and not l.strip().startswith("#") and "flush ruleset" not in l
                                         and not l.startswith("#!") for l in nft.splitlines()[1:]) and "table" in nft))
        ipt = self.read("/proc/net/ip_tables_names")
        if ipt is not None and ipt.strip():
            found.append(("iptables (kernel tables loaded)", True))
        if not found:
            self.add("firewall", "host-firewall", WARN, "no host firewall (ufw/firewalld/nftables/iptables) detected",
                     "Enable a host firewall, or confirm one is enforced upstream (e.g. cloud security groups).")
        elif any(on for _, on in found):
            self.add("firewall", "host-firewall", PASS, "active: " + ", ".join(n for n, on in found if on))
        else:
            self.add("firewall", "host-firewall", WARN, "installed but not detected as enabled: " + ", ".join(n for n, _ in found),
                     "Enable the firewall and verify with its own status command.")

    # ---- unattended upgrades
    def check_updates(self):
        apt = self.read("/etc/apt/apt.conf.d/20auto-upgrades")
        dnf = self.read("/etc/dnf/automatic.conf")
        if apt is not None:
            on = any("Unattended-Upgrade" in l and '"1"' in l for l in apt.splitlines() if not l.strip().startswith("//"))
            self.add("updates", "unattended-upgrades", PASS if on else WARN,
                     "APT periodic unattended-upgrade enabled" if on else "20auto-upgrades present but unattended-upgrade not set to \"1\"",
                     "" if on else "Run 'dpkg-reconfigure unattended-upgrades' (hint only).")
        elif dnf is not None:
            timers = glob.glob(self.p("/etc/systemd/system/timers.target.wants/dnf-automatic*.timer"))
            self.add("updates", "unattended-upgrades", PASS if timers else WARN,
                     "dnf-automatic timer enabled" if timers else "dnf-automatic installed but timer not enabled",
                     "" if timers else "Enable dnf-automatic.timer (hint only).")
        elif os.path.exists(self.p("/usr/bin/unattended-upgrade")):
            self.add("updates", "unattended-upgrades", WARN, "unattended-upgrades installed but not configured")
        else:
            self.add("updates", "unattended-upgrades", WARN, "no automatic update mechanism detected (apt/dnf)",
                     "Install and enable unattended-upgrades or dnf-automatic, or confirm patching is handled elsewhere.")

    # ---- kernel
    def check_kernel(self):
        v = self.read("/proc/sys/kernel/randomize_va_space")
        if v is None:
            self.add("kernel", "aslr", SKIP, "randomize_va_space not readable")
        else:
            v = v.strip()
            self.add("kernel", "aslr", PASS if v == "2" else FAIL if v == "0" else WARN, f"kernel.randomize_va_space={v}",
                     "" if v == "2" else "Set kernel.randomize_va_space=2 (hint only).")

    def run(self):
        self.results = []
        for fn in (self.check_ssh, self.check_file_modes, self.check_accounts, self.check_firewall,
                   self.check_updates, self.check_kernel):
            fn()
        return self.results


def summarize(results):
    out = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
    for r in results:
        out[r["status"]] += 1
    return out


def exit_code(results, strict=False):
    s = summarize(results)
    return 1 if s[FAIL] or (strict and s[WARN]) else 0


def format_report(results):
    lines = ["Linux hardening audit (read-only)", "=" * 33]
    for r in results:
        lines.append(f"[{r['status']:<4}] {r['area']:<9} {r['check']:<24} {r['detail']}")
        if r["hint"] and r["status"] in (WARN, FAIL):
            lines.append(f"         hint: {r['hint']}")
    s = summarize(results)
    lines.append("")
    lines.append(f"{s[PASS]} pass, {s[WARN]} warn, {s[FAIL]} fail, {s[SKIP]} skipped")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only Linux hardening audit. Never modifies the system.",
                                 epilog="Exit codes: 0 ok, 1 FAIL found (or WARN with --strict), 2 usage error.")
    ap.add_argument("--root", default="/", help="audit a filesystem tree rooted here instead of / (for testing/mounted images)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="treat WARN as failure for the exit code")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.root):
        print(f"error: --root {a.root} is not a directory", file=sys.stderr)
        return 2
    results = Audit(a.root).run()
    if a.json:
        print(json.dumps({"summary": summarize(results), "results": results}, indent=2))
    else:
        print(format_report(results))
    return exit_code(results, a.strict)


if __name__ == "__main__":
    sys.exit(main())
