# Branch scope: nftables / Qt5 (qmake, 5.3.8 line)

This branch is a slimmed-down fwbuilder tree. It keeps only the firewall
platforms and host operating systems that this fork targets.

## Supported firewall platforms

| Platform   | Compiler binary | Notes                                  |
|------------|-----------------|----------------------------------------|
| iptables   | fwb_ipt         | Linux netfilter (legacy)               |
| nftables   | fwb_nft         | native nftables backend (this branch)  |
| pf         | fwb_pf          | BSD packet filter                      |
| ipf        | fwb_ipf         | BSD ipfilter                           |
| ipfw       | fwb_ipfw        | BSD ipfw, also used for macOS/Solaris  |

## Supported host OS families

- Linux (linux24, linux317)
- OpenWRT (openwrt)
- FreeBSD, OpenBSD, macOS X, Solaris (BSD compiler line)
- unknown_os (generic templates)

## Removed in this branch

- Cisco: pix, fwsm, iosacl, nxosacl (compilers, importers, dialogs, installers)
- Juniper: junosacl
- HP ProCurve: procurve_acl
- Embedded host OSes: dd-wrt (nvram/jffs), secuwall (secunet wall), ipcop,
  sveasoft (Linksys)
- endian, oneshield OS definitions

The commit history documents the removals; the sources were dropped from the
tree entirely so they cannot silently regress.

## CI

`.github/workflows/build-qt5.yml` builds the full tree with Qt5/qmake on
Ubuntu, inventories the compiled policy compilers (fwb_ipt, fwb_pf, fwb_ipf,
fwb_ipfw, fwb_nft), and runs the native nftables smoke tests plus the
generated-script fixture matrix. On failures it publishes configure/build
logs to the `ci-logs-nftables` branch.
