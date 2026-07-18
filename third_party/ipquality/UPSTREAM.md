# IPQuality upstream

- Project: `xykt/IPQuality`
- Source: https://github.com/xykt/IPQuality
- Pinned commit: `44c35cca002782ddd6364e039be2949a2535d1cc`
- Upstream script version: `v2026-03-29`
- Upstream `ip.sh` SHA-256 before local changes: `a726997f3a445a346a0a92ae2b62af0e18d1c0a3811dab37cbb38c9def8803ae`
- License: AGPL-3.0; see `LICENSE` in this directory.

## Local integration changes

The bundled source remains readable in `ip.sh`. The local integration:

1. Pins downloaded reference data to the same upstream commit.
2. Skips advertising and online report upload in embedded mode.
3. Parses connection options before any public-IP lookup in embedded mode. Proxy checks therefore do not first query the computer's direct public IP, while an omitted proxy option explicitly initializes a direct check after parsing.
4. Routes the ISO-3166 reference download through the selected proxy.
5. Replaces hundreds of short-lived `dig` processes with one bounded concurrent DNSBL helper in embedded mode; the pinned upstream DNSBL list and result categories are unchanged.
6. Uses the embedded helper for China Standard Time because the trimmed Windows runtime intentionally omits the system timezone database.
7. Skips the upstream usage-counter request in embedded mode; it is telemetry rather than a detection module.

Set `IPQUALITY_EMBEDDED=1` when launching the script to enable these integration changes. The GUI also passes the upstream privacy option `-p`.
