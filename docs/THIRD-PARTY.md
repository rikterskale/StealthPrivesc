# Third-party material

* `src/ThirdParty/PrivescCheck/CodeIntegrity.ps1`: BSD-3-Clause parser by itm4n, crediting Matthew Graeber, James Forshaw and Gerhart. Pinned revision and original license accompany the file. Local changes expose OptionFlags and replace a residual unavailable custom type with PSObject. The isolated wrapper supplies hex conversion and records parser warnings.
* `data/reference/drivers.json`: reduced LOLDrivers metadata under Apache-2.0, with accompanying license. Identity, hashes, signing metadata and advisory references only; no binaries or commands.
* `data/reference/lolbas.json`: reduced LOLBAS names and discovery paths. GPL-3.0 license and project notice accompany this separate dataset. Transformation source is `tools/Update-ReferenceData.ps1`; upstream source is linked in the snapshot.
* `data/reference/windows-updates.json` and `kb-builds.json`: factual Microsoft CVRF/KB-derived records with source URLs and retrieval timestamps. Finite snapshots, not a Microsoft-supported applicability engine.

Windows DLLs and installed Mozilla NSS are invoked through their APIs and are not redistributed.
