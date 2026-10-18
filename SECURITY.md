# Security policy

## Scope and safety
read-only: reads config files, file modes and `/proc/sys`; runs no commands, opens no network connections, never modifies the system and never prints password hashes. Hints are text only.

## What was and was not tested
**Tested (automated, in CI and locally):** every check against fake filesystem trees built in temporary directories, a byte-for-byte 'tree unchanged' test, and one run on the development container's real `/`.

**Not tested:** a range of real distributions and hardened production hosts, SSH `Match` blocks, runtime firewall state, and running as root against real `/etc/shadow` on a multi-user system.

## Reporting a problem
This is a small personal portfolio project, not a supported product. If you find a security issue, please open a GitHub issue **without** secrets, credentials or real system details, or use GitHub's "Report a vulnerability" button on the Security tab if it is enabled.
