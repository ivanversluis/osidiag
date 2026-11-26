# Security policy

Please report suspected vulnerabilities privately using GitHub's
**Report a vulnerability** feature, if enabled, rather than opening a public issue.

The CI workflow runs static analysis, vulnerability checks, unit tests and
cross-compilation. CI is not a substitute for runtime testing or security review.

L3 uses Linux raw ICMP sockets. Grant only CAP_NET_RAW when required;
avoid running the full diagnostic utility as root. Network probes must
only target systems you are authorized to test.
