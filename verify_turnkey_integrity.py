#!/usr/bin/env python3
"""
Standalone Zero-Dependency Turnkey Benchmark Integrity Auditor
==============================================================
Cryptographically verifies SHA-256 digests, namespace-agnostic CDISC ODM v1.3.2 &
Veeva Vault CDMS XML structures, TransCelerate USDM v3.0 JSON schemas, OpenXML `.xlsx`
workbooks (Medidata Rave ALS & 21 CFR Part 11 Provenance Matrix), Dual-Canvas Playwright
vector diagrams (`canvas_standard.svg`/`.pdf` vs. `canvas_mindmap.svg`/`.pdf`), and
Zero-IP repository hygiene using ONLY the Python 3 Standard Library.

Usage:
    python3 verify_turnkey_integrity.py [--repo-dir .]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Dict, List, Set, Tuple

REQUIRED_9_ARTIFACTS: Tuple[str, ...] = (
    "exports/rave_als.xlsx",
    "exports/veeva_cdms.xml",
    "exports/cdisc_odm_v1.3.2.xml",
    "exports/transcelerate_usdm_v3.0.json",
    "metadata/provenance_matrix_21cfr11.xlsx",
    "visuals/canvas_standard.svg",
    "visuals/canvas_standard.pdf",
    "visuals/canvas_mindmap.svg",
    "visuals/canvas_mindmap.pdf",
)

REQUIRED_11_STUDY_FILES: Tuple[str, ...] = REQUIRED_9_ARTIFACTS + (
    "metadata/compilation_manifest.json",
    "README.md",
)

ALLOWED_ROOT_FILES: Set[str] = {
    "README.md",
    "LICENSE",
    "benchmark_manifest.json",
    "verify_turnkey_integrity.py",
    ".gitignore",
}

FORBIDDEN_EXTENSIONS: Set[str] = {
    ".wasm",
    ".so",
    ".dylib",
    ".dll",
    ".pyc",
    ".pyo",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".env",
    ".pem",
    ".key",
    ".enc",
    ".ts",
    ".tsx",
    ".js",
    ".sh",
}

FORBIDDEN_PROMPT_AND_SECRET_MARKERS: Tuple[str, ...] = (
    "SYSTEM_" + "PROMPT",
    "You are an expert " + "clinical",
    "SCRIBE_" + "VAULT",
    "[REDACTED_" + "VAULT_SECRET]",
    "BEGIN RSA " + "PRIVATE KEY",
    "BEGIN OPENSSH " + "PRIVATE KEY",
    "postgresql:" + "//",
    "minio" + "admin",
    "sk-" + "proj-",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


def local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _check_openxml_xlsx(xlsx_path: Path, label: str, errors: List[str]) -> None:
    if not zipfile.is_zipfile(xlsx_path):
        errors.append(f"{label}: '{xlsx_path}' is not a valid OpenXML ZIP archive.")
        return
    try:
        with zipfile.ZipFile(xlsx_path, "r") as zf:
            names = set(zf.namelist())
            if "xl/workbook.xml" not in names:
                errors.append(f"{label}: '{xlsx_path}' missing 'xl/workbook.xml'.")
                return
            wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
            sheets = [el for el in wb_root.iter() if local_name(el.tag) == "sheet"]
            if not sheets:
                errors.append(f"{label}: '{xlsx_path}' workbook contains zero worksheet definitions.")
    except Exception as exc:
        errors.append(f"{label}: failed to inspect OpenXML workbook '{xlsx_path}': {exc}")


def _check_cdisc_odm_xml(xml_path: Path, nct_id: str, errors: List[str]) -> None:
    try:
        root = ET.fromstring(xml_path.read_bytes())
    except Exception as exc:
        errors.append(f"[{nct_id}] Invalid XML in '{xml_path.name}': {exc}")
        return
    if local_name(root.tag) != "ODM":
        errors.append(f"[{nct_id}] '{xml_path.name}' root tag must be 'ODM', got '{local_name(root.tag)}'.")
    found_tags = {local_name(el.tag) for el in root.iter()}
    for req_tag in ("Study", "MetaDataVersion", "FormDef", "ItemDef"):
        if req_tag not in found_tags:
            errors.append(f"[{nct_id}] '{xml_path.name}' missing required ODM element '<{req_tag}>'.")


def _check_veeva_xml(xml_path: Path, nct_id: str, errors: List[str]) -> None:
    try:
        root = ET.fromstring(xml_path.read_bytes())
    except Exception as exc:
        errors.append(f"[{nct_id}] Invalid XML in '{xml_path.name}': {exc}")
        return
    rname = local_name(root.tag)
    found_tags = {local_name(el.tag) for el in root.iter()}
    is_veeva_native = (
        rname == "VeevaCDMS"
        and bool(root.attrib.get("study"))
        and {"Forms", "Form", "ItemGroup", "Item"}.issubset(found_tags)
    )
    is_odm_compat = (
        rname == "ODM"
        and {"Study", "MetaDataVersion", "FormDef", "ItemDef"}.issubset(found_tags)
    )
    if not (is_veeva_native or is_odm_compat):
        errors.append(
            f"[{nct_id}] '{xml_path.name}' missing required Veeva CDMS Forms/Items or ODM definitions."
        )


def _check_usdm_json(json_path: Path, nct_id: str, errors: List[str]) -> None:
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"[{nct_id}] Invalid JSON in '{json_path.name}': {exc}")
        return
    if not isinstance(data, dict):
        errors.append(f"[{nct_id}] '{json_path.name}' root must be a JSON object.")
        return
    study = data.get("study")
    study_designs = study.get("studyDesigns") if isinstance(study, dict) else None
    if not data.get("usdmVersion") or not isinstance(study_designs, list) or len(study_designs) == 0:
        errors.append(
            f"[{nct_id}] '{json_path.name}' missing non-empty USDM v3.0 'study.studyDesigns' array."
        )


def _check_dual_canvas_visuals(study_dir: Path, nct_id: str, errors: List[str]) -> None:
    std_svg = study_dir / "visuals" / "canvas_standard.svg"
    mm_svg = study_dir / "visuals" / "canvas_mindmap.svg"
    std_pdf = study_dir / "visuals" / "canvas_standard.pdf"
    mm_pdf = study_dir / "visuals" / "canvas_mindmap.pdf"

    for svg_p in (std_svg, mm_svg):
        if not svg_p.is_file():
            continue
        try:
            s_root = ET.fromstring(svg_p.read_bytes())
            if local_name(s_root.tag).lower() != "svg" or len(list(s_root)) == 0:
                errors.append(f"[{nct_id}] '{svg_p.name}' is not a non-empty '<svg>' document.")
        except Exception as exc:
            errors.append(f"[{nct_id}] Malformed SVG XML in '{svg_p.name}': {exc}")

    if std_svg.is_file() and mm_svg.is_file():
        if sha256_file(std_svg) == sha256_file(mm_svg):
            errors.append(
                f"[{nct_id}] canvas_standard.svg and canvas_mindmap.svg have identical SHA-256 digests "
                "(distinct chronological vs. mind_map topologies required)."
            )

    for pdf_p in (std_pdf, mm_pdf):
        if not pdf_p.is_file():
            continue
        head = pdf_p.read_bytes()[:5]
        if head != b"%PDF-":
            errors.append(f"[{nct_id}] '{pdf_p.name}' missing '%PDF-' magic header.")


def _check_zero_ip_sanitization(repo_dir: Path, expected_study_ids: Set[str], errors: List[str]) -> None:
    text_suffixes = {".md", ".json", ".xml", ".svg", ".txt", ".csv", ".yaml", ".yml", ".html"}
    for path in sorted(repo_dir.rglob("*")):
        rel_parts = path.relative_to(repo_dir).parts
        if ".git" in rel_parts:
            continue
        if path.is_dir():
            continue

        rel_str = path.relative_to(repo_dir).as_posix()
        fname = path.name
        suffix = path.suffix.lower()

        if fname.startswith(".env") or fname == ".scribe_vault.enc" or suffix in FORBIDDEN_EXTENSIONS:
            errors.append(f"[ZERO-IP VIOLATION] Forbidden binary/database/secret file detected: '{rel_str}'.")
            continue

        if suffix == ".py" and rel_str != "verify_turnkey_integrity.py":
            errors.append(f"[ZERO-IP VIOLATION] Unauthorized Python script detected: '{rel_str}'.")
            continue

        if len(rel_parts) == 1 and fname not in ALLOWED_ROOT_FILES:
            errors.append(f"[ZERO-IP VIOLATION] Unexpected root file detected: '{rel_str}'.")
            continue

        if len(rel_parts) >= 2 and rel_parts[0] == "studies":
            study_id = rel_parts[1]
            study_rel = "/".join(rel_parts[2:])
            if study_id not in expected_study_ids:
                errors.append(f"[ZERO-IP VIOLATION] Unindexed study directory file: '{rel_str}'.")
                continue
            if study_rel not in REQUIRED_11_STUDY_FILES:
                errors.append(f"[ZERO-IP VIOLATION] Unexpected file inside study folder: '{rel_str}'.")
                continue

        if rel_str != "verify_turnkey_integrity.py" and (suffix in text_suffixes or fname == "LICENSE"):
            try:
                text_body = path.read_text(encoding="utf-8", errors="ignore")
                for marker in FORBIDDEN_PROMPT_AND_SECRET_MARKERS:
                    if marker.lower() in text_body.lower():
                        errors.append(
                            f"[ZERO-IP VIOLATION] Forbidden prompt/secret marker '{marker}' found in '{rel_str}'."
                        )
            except Exception as exc:
                errors.append(f"[ZERO-IP VIOLATION] Could not scan '{rel_str}': {exc}")


def verify_repository(repo_dir: Path) -> Tuple[bool, List[str]]:
    repo_dir = Path(repo_dir).resolve()
    errors: List[str] = []

    for req_root in ("README.md", "LICENSE", "benchmark_manifest.json", "verify_turnkey_integrity.py"):
        p = repo_dir / req_root
        if not p.is_file() or p.stat().st_size == 0:
            errors.append(f"Missing or empty required root file: '{req_root}'.")

    bm_path = repo_dir / "benchmark_manifest.json"
    if not bm_path.is_file():
        return False, errors

    try:
        bm = json.loads(bm_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, [f"Malformed JSON in benchmark_manifest.json: {exc}"]

    studies = bm.get("studies", [])
    if not isinstance(studies, list) or len(studies) == 0:
        errors.append("benchmark_manifest.json contains zero studies.")
        return False, errors

    expected_study_ids: Set[str] = set()
    for st in studies:
        nct_id = str(st.get("nct_id") or "")
        expected_study_ids.add(nct_id)
        study_dir = repo_dir / "studies" / nct_id
        if not study_dir.is_dir():
            errors.append(f"[{nct_id}] Missing study directory: {study_dir}")
            continue

        # 1a. Verify 11 study files in root benchmark_manifest.json
        st_files: Dict[str, Any] = st.get("files", {})
        if set(st_files.keys()) != set(REQUIRED_11_STUDY_FILES):
            errors.append(
                f"[{nct_id}] benchmark_manifest.json must index exact 11 study files, got {sorted(st_files.keys())}."
            )
        for rel_f in REQUIRED_11_STUDY_FILES:
            fpath = study_dir / rel_f
            if not fpath.is_file() or fpath.stat().st_size == 0:
                errors.append(f"[{nct_id}] Missing or empty study file: '{rel_f}'.")
                continue
            expected_sha = (st_files.get(rel_f) or {}).get("sha256")
            actual_sha = sha256_file(fpath)
            if expected_sha != actual_sha:
                errors.append(
                    f"[{nct_id}] SHA-256 mismatch in benchmark_manifest.json for '{rel_f}': "
                    f"expected {expected_sha}, got {actual_sha}."
                )

        # 1b. Verify 9 sibling artifacts in studies/<NCT_ID>/metadata/compilation_manifest.json
        cm_path = study_dir / "metadata" / "compilation_manifest.json"
        if cm_path.is_file():
            try:
                cm = json.loads(cm_path.read_text(encoding="utf-8"))
                cm_artifacts: Dict[str, Any] = cm.get("artifacts", {})
                if "metadata/compilation_manifest.json" in cm_artifacts:
                    errors.append(f"[{nct_id}] Circular self-hash forbidden in compilation_manifest.json.")
                if set(cm_artifacts.keys()) != set(REQUIRED_9_ARTIFACTS):
                    errors.append(
                        f"[{nct_id}] compilation_manifest.json must index exact 9 sibling artifacts, "
                        f"got {sorted(cm_artifacts.keys())}."
                    )
                for rel_a in REQUIRED_9_ARTIFACTS:
                    apath = study_dir / rel_a
                    if apath.is_file():
                        exp_a_sha = (cm_artifacts.get(rel_a) or {}).get("sha256")
                        act_a_sha = sha256_file(apath)
                        if exp_a_sha != act_a_sha:
                            errors.append(
                                f"[{nct_id}] SHA-256 mismatch in compilation_manifest.json for '{rel_a}': "
                                f"expected {exp_a_sha}, got {act_a_sha}."
                            )
            except Exception as exc:
                errors.append(f"[{nct_id}] Malformed compilation_manifest.json: {exc}")

        # 2. Structural checks across XML, JSON, OpenXML XLSX, and Dual-Canvas SVG/PDF
        odm_xml = study_dir / "exports" / "cdisc_odm_v1.3.2.xml"
        if odm_xml.is_file():
            _check_cdisc_odm_xml(odm_xml, nct_id, errors)

        veeva_xml = study_dir / "exports" / "veeva_cdms.xml"
        if veeva_xml.is_file():
            _check_veeva_xml(veeva_xml, nct_id, errors)

        usdm_json = study_dir / "exports" / "transcelerate_usdm_v3.0.json"
        if usdm_json.is_file():
            _check_usdm_json(usdm_json, nct_id, errors)

        rave_xlsx = study_dir / "exports" / "rave_als.xlsx"
        if rave_xlsx.is_file():
            _check_openxml_xlsx(rave_xlsx, f"[{nct_id}] Rave ALS", errors)

        prov_xlsx = study_dir / "metadata" / "provenance_matrix_21cfr11.xlsx"
        if prov_xlsx.is_file():
            _check_openxml_xlsx(prov_xlsx, f"[{nct_id}] 21 CFR Part 11 Provenance Matrix", errors)

        _check_dual_canvas_visuals(study_dir, nct_id, errors)

    # 3. Zero-IP repository-wide scan
    _check_zero_ip_sanitization(repo_dir, expected_study_ids, errors)

    return len(errors) == 0, errors


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify cryptographic and structural integrity of G-Flow Open Protocol Benchmarks."
    )
    parser.add_argument(
        "--repo-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Root directory of the benchmark repository.",
    )
    args = parser.parse_args(argv)
    passed, errors = verify_repository(args.repo_dir)
    if passed:
        bm = json.loads((Path(args.repo_dir).resolve() / "benchmark_manifest.json").read_text("utf-8"))
        n_studies = len(bm.get("studies", []))
        print(
            f"[PASS] Verified 100% cryptographic, structural, Dual-Canvas SVG/PDF, and Zero-IP integrity "
            f"across {n_studies} studies ({n_studies * 11} study files)."
        )
        return 0

    print(f"[FAIL] Integrity verification failed with {len(errors)} error(s):", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
