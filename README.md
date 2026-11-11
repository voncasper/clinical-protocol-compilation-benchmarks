# Open Clinical Protocol Compilation Benchmarks

Public, zero-trust clinical trial compilation benchmark published by **VonCasper Solutions**.
Every study directory in this repository contains the machine-readable turnkey study build compiled
from raw public [ClinicalTrials.gov](https://clinicaltrials.gov) Protocol PDFs in a **single unassisted pass (`--no-resume`)**:

1. **Medidata Rave Architect Loader Spreadsheet (`.xlsx`)** — `exports/rave_als.xlsx`
2. **Veeva Vault CDMS Study Definition (`.xml`)** — `exports/veeva_cdms.xml`
3. **CDISC ODM-XML v1.3.2 Standard Export (`.xml`)** — `exports/cdisc_odm_v1.3.2.xml`
4. **TransCelerate Digital Data Flow USDM v3.0 (`.json`)** — `exports/transcelerate_usdm_v3.0.json`
5. **21 CFR Part 11 eCRF-to-PDF Bounding-Box Provenance Matrix (`.xlsx`)** — `metadata/provenance_matrix_21cfr11.xlsx`
6. **Dual-Canvas Vector Study Topologies (`SVG` + `PDF`)** — `visuals/canvas_standard.{svg,pdf}` & `visuals/canvas_mindmap.{svg,pdf}`

## Zero-Dependency External Auditor Quickstart

Any clinical data manager, biostatistician, or regulatory auditor can cryptographically verify
every SHA-256 digest, XML/JSON/OpenXML schema, Dual-Canvas SVG/PDF topology, and Zero-IP invariant
using only the Python 3 Standard Library:

```bash
python3 verify_turnkey_integrity.py
# Forensic Dual-Layer OpenXML Watermark Inspection (survives file rename & Excel edits):
python3 verify_turnkey_integrity.py --inspect-watermark studies/NCT01631552/exports/rave_als.xlsx
```

*Last Manifest Finalization (UTC): `2026-11-11T20:33:07.129186+00:00`*

---

## Section I — Foundational Clinical Trial Design Archetypes (Canonical Reference Studies)

These industry-standard reference trials (spanning parallel randomized arms, 3+3 CAR-T dose escalation,
2x2 washout crossovers, multi-cyclic `Q3W`/`Q4W` oncology, and adaptive pharmacodynamic titration,
including pre-2020 foundational trials) validate topological compiler completeness across all 5 canonical geometries.

| NCT ID | Archetype Category | ClinicalTrials.gov Record & CDN PDF | Protocol SHA-256 (`study_<sha8>`) | Forms / Items | Dual-Canvas Visuals & Study Dossier |
| :--- | :--- | :--- | :--- | :---: | :--- |
| [`NCT04891770`](./studies/NCT04891770/README.md) | Archetype 1: Parallel Randomized Arms | [Record](https://clinicaltrials.gov/study/NCT04891770) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/70/NCT04891770/Prot_000.pdf) | `f115ce87...` (`study_f115ce87`) | `15` / `84` | [Dossier](./studies/NCT04891770/README.md) · [Standard SVG](./studies/NCT04891770/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT04891770/visuals/canvas_mindmap.svg) |
| [`NCT03084237`](./studies/NCT03084237/README.md) | Archetype 1: Parallel Randomized Arms | [Record](https://clinicaltrials.gov/study/NCT03084237) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/37/NCT03084237/Prot_SAP_000.pdf) | `6cff1fe3...` (`study_6cff1fe3`) | `15` / `85` | [Dossier](./studies/NCT03084237/README.md) · [Standard SVG](./studies/NCT03084237/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT03084237/visuals/canvas_mindmap.svg) |
| [`NCT04030195`](./studies/NCT04030195/README.md) | Archetype 2: CAR-T Multi-Cohort 3+3 Dose Escalation | [Record](https://clinicaltrials.gov/study/NCT04030195) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/95/NCT04030195/Prot_000.pdf) | `3fc386fd...` (`study_3fc386fd`) | `15` / `75` | [Dossier](./studies/NCT04030195/README.md) · [Standard SVG](./studies/NCT04030195/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT04030195/visuals/canvas_mindmap.svg) |
| [`NCT03226275`](./studies/NCT03226275/README.md) | Archetype 3: 2x2 Crossover with Washout Period | [Record](https://clinicaltrials.gov/study/NCT03226275) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/75/NCT03226275/Prot_000.pdf) | `6d342d6d...` (`study_6d342d6d`) | `15` / `73` | [Dossier](./studies/NCT03226275/README.md) · [Standard SVG](./studies/NCT03226275/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT03226275/visuals/canvas_mindmap.svg) |
| [`NCT01631552`](./studies/NCT01631552/README.md) | Archetype 4: Multi-Cyclic Oncology (Q3W/Q4W) | [Record](https://clinicaltrials.gov/study/NCT01631552) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/52/NCT01631552/Prot_000.pdf) | `53457f06...` (`study_53457f06`) | `15` / `48` | [Dossier](./studies/NCT01631552/README.md) · [Standard SVG](./studies/NCT01631552/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT01631552/visuals/canvas_mindmap.svg) |
| [`NCT01772472`](./studies/NCT01772472/README.md) | Archetype 4: Multi-Cyclic Oncology (Q3W/Q4W) | [Record](https://clinicaltrials.gov/study/NCT01772472) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/72/NCT01772472/Prot_000.pdf) | `51072f90...` (`study_51072f90`) | `15` / `73` | [Dossier](./studies/NCT01772472/README.md) · [Standard SVG](./studies/NCT01772472/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT01772472/visuals/canvas_mindmap.svg) |
| [`NCT03922750`](./studies/NCT03922750/README.md) | Archetype 5: Adaptive Titration & Branching | [Record](https://clinicaltrials.gov/study/NCT03922750) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/50/NCT03922750/Prot_000.pdf) | `6785f6da...` (`study_6785f6da`) | `15` / `43` | [Dossier](./studies/NCT03922750/README.md) · [Standard SVG](./studies/NCT03922750/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT03922750/visuals/canvas_mindmap.svg) |
| [`NCT02365597`](./studies/NCT02365597/README.md) | Archetype 5: Adaptive Titration & Branching | [Record](https://clinicaltrials.gov/study/NCT02365597) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/97/NCT02365597/Prot_000.pdf) | `75af2dbc...` (`study_75af2dbc`) | `15` / `81` | [Dossier](./studies/NCT02365597/README.md) · [Standard SVG](./studies/NCT02365597/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT02365597/visuals/canvas_mindmap.svg) |

---

## Section II — Modern (`2020+`) Single-Pass Parity Suite & Live Community Challenge Submissions

Modern clinical study designs (`2020+` ICH E6(R2)/(R3) & CDASH/SDTM era, plus historical parity control
`NCT02295735` and live community challenge submissions compiled on-demand via `--add-nct`).

| NCT ID | Suite / Challenge Category | ClinicalTrials.gov Record & CDN PDF | Protocol SHA-256 (`study_<sha8>`) | Forms / Items | Dual-Canvas Visuals & Study Dossier |
| :--- | :--- | :--- | :--- | :---: | :--- |
| [`NCT07515196`](./studies/NCT07515196/README.md) | Live Single-Pass Parity Suite | [Record](https://clinicaltrials.gov/study/NCT07515196) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/96/NCT07515196/Prot_SAP_000.pdf) | `a4f4b299...` (`study_a4f4b299`) | `15` / `61` | [Dossier](./studies/NCT07515196/README.md) · [Standard SVG](./studies/NCT07515196/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT07515196/visuals/canvas_mindmap.svg) |
| [`NCT04681482`](./studies/NCT04681482/README.md) | Live Single-Pass Parity Suite | [Record](https://clinicaltrials.gov/study/NCT04681482) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/82/NCT04681482/Prot_SAP_000.pdf) | `407ab016...` (`study_407ab016`) | `15` / `57` | [Dossier](./studies/NCT04681482/README.md) · [Standard SVG](./studies/NCT04681482/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT04681482/visuals/canvas_mindmap.svg) |
| [`NCT05460650`](./studies/NCT05460650/README.md) | Live Single-Pass Parity Suite | [Record](https://clinicaltrials.gov/study/NCT05460650) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/50/NCT05460650/Prot_SAP_000.pdf) | `e87816cb...` (`study_e87816cb`) | `15` / `41` | [Dossier](./studies/NCT05460650/README.md) · [Standard SVG](./studies/NCT05460650/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT05460650/visuals/canvas_mindmap.svg) |
| [`NCT05307783`](./studies/NCT05307783/README.md) | Live Single-Pass Parity Suite | [Record](https://clinicaltrials.gov/study/NCT05307783) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/83/NCT05307783/Prot_000.pdf) | `5fc98924...` (`study_5fc98924`) | `15` / `61` | [Dossier](./studies/NCT05307783/README.md) · [Standard SVG](./studies/NCT05307783/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT05307783/visuals/canvas_mindmap.svg) |
| [`NCT02295735`](./studies/NCT02295735/README.md) | Live Single-Pass Parity Suite (Historical Parity Control) | [Record](https://clinicaltrials.gov/study/NCT02295735) · [CDN PDF](https://cdn.clinicaltrials.gov/large-docs/35/NCT02295735/Prot_SAP_000.pdf) | `7e9b8990...` (`study_7e9b8990`) | `15` / `64` | [Dossier](./studies/NCT02295735/README.md) · [Standard SVG](./studies/NCT02295735/visuals/canvas_standard.svg) · [Mind Map SVG](./studies/NCT02295735/visuals/canvas_mindmap.svg) |

---

## License

Compiled benchmark schemas, provenance matrices, vector diagrams, and verification tooling are licensed
under the [Apache License 2.0](./LICENSE) by **VonCasper Solutions**.
