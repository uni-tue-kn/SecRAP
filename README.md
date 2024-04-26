# SecRAP
SecRAP implementation
This repository contains the implementation of security extensions for the Resource Allocation Protocol (RAP, IEEE 802.1Qdd) of Time-sensitive Networking (TSN).
It is a contribution of the publication "Secure Resource Allocation Protocol (SecRAP) for Time-Sensitive Networking".

***

# Organization
The repository consists of three parts:
- ecp-tls (License: Apache v2)
  - Contains the implementation of ETLS using eBPF in Rust
- ebpf-helper (License: Apache v2)
  - Contains helper functions for programming eBPF-based prototypes
- rap (License: GPLv3)
  - Contains a user-space RAP packet generator/receiver with the end-to-end integrity protection implementation
 

