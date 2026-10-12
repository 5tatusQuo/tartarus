# Optional external traffic capture

Tartarus does not modify Proxmox bridges, switch port mirroring, or bridge
ageing. The supported baseline captures experiment traffic on REMnux and
records that observer boundary in each run.

An operator who needs an independent vSwitch observation point must treat it
as host maintenance: follow the networking procedure for the installed Ludus
and Proxmox versions, obtain separate administrative approval, record the host
change outside Tartarus, and revert it after the capture window. Do not pass
Proxmox credentials into a guest or add a host command to a Tartarus role.

Before using externally captured data as evidence, record its interface and
time interval, copy it into the run with `tartarus run collect`, and retain its
artifact record. External capture is never required for the compact
profile and is outside automated deployment and recovery.
