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
    python3 verify_turnkey_integrity.py --inspect-watermark studies/NCT01631552/exports/rave_als.xlsx
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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


WATERMARK_SHEET_NAME = "_GFlow_Provenance"


def compute_watermark_digest(nct_id: str, design_id: str, protocol_sha256: str) -> str:
    payload = f"VonCasper Solutions|Vincent Capers Jr.|{nct_id}|{design_id}|{protocol_sha256}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def inspect_xlsx_watermark(xlsx_path: Path) -> Dict[str, Any]:
    xlsx_path = Path(xlsx_path)
    errors: List[str] = []
    core_props: Dict[str, str] = {}
    layer1_props: Dict[str, str] = {}
    layer2_props: Dict[str, str] = {}
    layer2_found = False
    layer2_state: Optional[str] = None

    if not xlsx_path.is_file():
        return {
            "file": str(xlsx_path),
            "file_sha256": None,
            "verified": False,
            "status": "WATERMARK VERIFICATION FAILED",
            "expected_watermark_digest": None,
            "layer1_core_properties": core_props,
            "layer1_custom_properties": layer1_props,
            "layer1_valid": False,
            "layer2_sheet_name": None,
            "layer2_sheet_state": None,
            "layer2_properties": layer2_props,
            "layer2_valid": False,
            "errors": [f"File does not exist: '{xlsx_path}'."],
        }

    file_sha = sha256_file(xlsx_path)
    if not zipfile.is_zipfile(xlsx_path):
        return {
            "file": str(xlsx_path),
            "file_sha256": file_sha,
            "verified": False,
            "status": "WATERMARK VERIFICATION FAILED",
            "expected_watermark_digest": None,
            "layer1_core_properties": core_props,
            "layer1_custom_properties": layer1_props,
            "layer1_valid": False,
            "layer2_sheet_name": None,
            "layer2_sheet_state": None,
            "layer2_properties": layer2_props,
            "layer2_valid": False,
            "errors": [f"'{xlsx_path}' is not a valid OpenXML ZIP archive."],
        }

    req_keys = (
        "GFlow_Watermark_Version",
        "GFlow_Assignee",
        "GFlow_Source_NCT_ID",
        "GFlow_Design_ID",
        "GFlow_Protocol_SHA256",
        "GFlow_Watermark_Digest",
    )

    try:
        with zipfile.ZipFile(xlsx_path, "r") as zf:
            names = set(zf.namelist())

            if "docProps/core.xml" in names:
                core_root = ET.fromstring(zf.read("docProps/core.xml"))
                for child in core_root:
                    val = (child.text or "").strip()
                    if val:
                        core_props[local_name(child.tag)] = val

            if "docProps/custom.xml" not in names:
                errors.append("Layer 1 missing: 'docProps/custom.xml' not found in workbook archive.")
            else:
                custom_root = ET.fromstring(zf.read("docProps/custom.xml"))
                for prop_el in custom_root:
                    if local_name(prop_el.tag) == "property":
                        pname = prop_el.attrib.get("name", "")
                        if pname:
                            layer1_props[pname] = "".join(prop_el.itertext()).strip()

            shared_strings: List[str] = []
            if "xl/sharedStrings.xml" in names:
                sst_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for si in sst_root:
                    if local_name(si.tag) == "si":
                        shared_strings.append(
                            "".join((t.text or "") for t in si.iter() if local_name(t.tag) == "t")
                        )

            if "xl/workbook.xml" not in names:
                errors.append("OpenXML workbook missing 'xl/workbook.xml'.")
            else:
                wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
                rel_map: Dict[str, str] = {}
                if "xl/_rels/workbook.xml.rels" in names:
                    rels_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
                    for rel_el in rels_root:
                        if local_name(rel_el.tag) == "Relationship":
                            rid = rel_el.attrib.get("Id", "")
                            rtarget = rel_el.attrib.get("Target", "")
                            if rid and rtarget:
                                rel_map[rid] = rtarget

                prov_sheet_el = None
                for sh in wb_root.iter():
                    if local_name(sh.tag) == "sheet" and sh.attrib.get("name") == WATERMARK_SHEET_NAME:
                        prov_sheet_el = sh
                        break

                if prov_sheet_el is None:
                    errors.append(
                        f"Layer 2 missing: worksheet '{WATERMARK_SHEET_NAME}' not declared in 'xl/workbook.xml'."
                    )
                else:
                    layer2_found = True
                    layer2_state = prov_sheet_el.attrib.get("state", "visible")
                    if layer2_state != "veryHidden":
                        errors.append(
                            f"Layer 2 visibility violation: '{WATERMARK_SHEET_NAME}' state must be 'veryHidden', "
                            f"got '{layer2_state}'."
                        )

                    rid_val = ""
                    for attr_k, attr_v in prov_sheet_el.attrib.items():
                        if local_name(attr_k) == "id":
                            rid_val = attr_v
                            break
                    raw_target = rel_map.get(rid_val, "")
                    norm_target = raw_target.lstrip("/")
                    if norm_target and not norm_target.startswith("xl/") and f"xl/{norm_target}" in names:
                        norm_target = f"xl/{norm_target}"

                    if not norm_target or norm_target not in names:
                        errors.append(
                            f"Layer 2 worksheet XML target '{raw_target}' (r:id='{rid_val}') missing from archive."
                        )
                    else:
                        ws_root = ET.fromstring(zf.read(norm_target))
                        for row_el in ws_root.iter():
                            if local_name(row_el.tag) != "row":
                                continue
                            cells: List[str] = []
                            for c_el in row_el:
                                if local_name(c_el.tag) != "c":
                                    continue
                                c_type = c_el.attrib.get("t", "")
                                if c_type == "inlineStr":
                                    c_val = "".join(
                                        (t.text or "") for t in c_el.iter() if local_name(t.tag) == "t"
                                    )
                                elif c_type == "s":
                                    v_nodes = [ch for ch in c_el if local_name(ch.tag) == "v"]
                                    idx_str = (v_nodes[0].text or "").strip() if v_nodes else ""
                                    c_val = (
                                        shared_strings[int(idx_str)]
                                        if idx_str.isdigit() and int(idx_str) < len(shared_strings)
                                        else ""
                                    )
                                else:
                                    v_nodes = [ch for ch in c_el if local_name(ch.tag) == "v"]
                                    c_val = (v_nodes[0].text or "") if v_nodes else ""
                                cells.append(c_val.strip())
                            if len(cells) >= 2 and cells[0] and cells[0] != "Property":
                                layer2_props[cells[0]] = cells[1]
    except Exception as exc:
        errors.append(f"Exception parsing OpenXML watermark structures: {exc}")

    layer1_valid = False
    expected_digest: Optional[str] = None
    missing_l1 = [k for k in req_keys if not layer1_props.get(k)]
    if missing_l1:
        errors.append(f"Layer 1 missing required custom properties: {missing_l1}.")
    elif "GFlow_CDN_Source_URL" not in layer1_props:
        errors.append("Layer 1 missing 'GFlow_CDN_Source_URL' custom property.")
    else:
        expected_digest = compute_watermark_digest(
            layer1_props["GFlow_Source_NCT_ID"],
            layer1_props["GFlow_Design_ID"],
            layer1_props["GFlow_Protocol_SHA256"],
        )
        if layer1_props["GFlow_Watermark_Digest"] != expected_digest:
            errors.append(
                f"Layer 1 digest mismatch: expected {expected_digest}, "
                f"got {layer1_props['GFlow_Watermark_Digest']}."
            )
        else:
            layer1_valid = True

    layer2_valid = False
    missing_l2 = [k for k in req_keys if not layer2_props.get(k)]
    if missing_l2:
        errors.append(f"Layer 2 missing required '{WATERMARK_SHEET_NAME}' rows: {missing_l2}.")
    else:
        expected_l2 = compute_watermark_digest(
            layer2_props["GFlow_Source_NCT_ID"],
            layer2_props["GFlow_Design_ID"],
            layer2_props["GFlow_Protocol_SHA256"],
        )
        if expected_digest is None:
            expected_digest = expected_l2
        if layer2_props["GFlow_Watermark_Digest"] != expected_l2:
            errors.append(
                f"Layer 2 digest mismatch: expected {expected_l2}, "
                f"got {layer2_props['GFlow_Watermark_Digest']}."
            )
        elif layer2_state == "veryHidden":
            layer2_valid = True

    if layer1_valid and layer2_valid:
        for sync_key in (
            "GFlow_Source_NCT_ID",
            "GFlow_Design_ID",
            "GFlow_Protocol_SHA256",
            "GFlow_Watermark_Digest",
        ):
            if layer1_props.get(sync_key) != layer2_props.get(sync_key):
                errors.append(
                    f"Cross-layer mismatch on '{sync_key}': Layer 1='{layer1_props.get(sync_key)}' "
                    f"vs Layer 2='{layer2_props.get(sync_key)}'."
                )
                layer1_valid = False
                layer2_valid = False

    verified = layer1_valid and layer2_valid and len(errors) == 0
    return {
        "file": str(xlsx_path),
        "file_sha256": file_sha,
        "verified": verified,
        "status": (
            "WATERMARK VERIFIED: AUTHENTIC G-FLOW COMPILATION"
            if verified
            else "WATERMARK VERIFICATION FAILED"
        ),
        "expected_watermark_digest": expected_digest,
        "layer1_core_properties": core_props,
        "layer1_custom_properties": layer1_props,
        "layer1_valid": layer1_valid,
        "layer2_sheet_name": WATERMARK_SHEET_NAME if layer2_found else None,
        "layer2_sheet_state": layer2_state,
        "layer2_properties": layer2_props,
        "layer2_valid": layer2_valid,
        "errors": errors,
    }


def _check_openxml_xlsx(
    xlsx_path: Path,
    label: str,
    errors: List[str],
    expected_nct_id: Optional[str] = None,
    expected_design_id: Optional[str] = None,
    expected_proto_sha: Optional[str] = None,
) -> None:
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
            visible_sheets = [
                s for s in sheets if s.attrib.get("name") != WATERMARK_SHEET_NAME
            ]
            if not visible_sheets:
                errors.append(f"{label}: '{xlsx_path}' workbook contains zero data worksheet definitions.")
    except Exception as exc:
        errors.append(f"{label}: failed to inspect OpenXML workbook '{xlsx_path}': {exc}")
        return

    wm = inspect_xlsx_watermark(xlsx_path)
    if not wm["verified"]:
        for werr in wm["errors"]:
            errors.append(f"{label}: {werr}")
        return

    l1 = wm["layer1_custom_properties"]
    if expected_nct_id and l1.get("GFlow_Source_NCT_ID") != expected_nct_id:
        errors.append(
            f"{label}: watermark NCT_ID '{l1.get('GFlow_Source_NCT_ID')}' != study '{expected_nct_id}'."
        )
    if expected_design_id and l1.get("GFlow_Design_ID") != expected_design_id:
        errors.append(
            f"{label}: watermark design_id '{l1.get('GFlow_Design_ID')}' != '{expected_design_id}'."
        )
    if expected_proto_sha and l1.get("GFlow_Protocol_SHA256") != expected_proto_sha:
        errors.append(
            f"{label}: watermark protocol_sha256 '{l1.get('GFlow_Protocol_SHA256')}' != '{expected_proto_sha}'."
        )


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
            _check_openxml_xlsx(
                rave_xlsx,
                f"[{nct_id}] Rave ALS",
                errors,
                expected_nct_id=nct_id,
                expected_design_id=str(st.get("design_id") or ""),
                expected_proto_sha=str(st.get("protocol_sha256") or ""),
            )

        prov_xlsx = study_dir / "metadata" / "provenance_matrix_21cfr11.xlsx"
        if prov_xlsx.is_file():
            _check_openxml_xlsx(
                prov_xlsx,
                f"[{nct_id}] 21 CFR Part 11 Provenance Matrix",
                errors,
                expected_nct_id=nct_id,
                expected_design_id=str(st.get("design_id") or ""),
                expected_proto_sha=str(st.get("protocol_sha256") or ""),
            )

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
    parser.add_argument(
        "--inspect-watermark",
        type=Path,
        default=None,
        help="Extract and cryptographically verify Dual-Layer OpenXML G-Flow provenance watermark from an .xlsx file.",
    )
    args = parser.parse_args(argv)

    if args.inspect_watermark is not None:
        report = inspect_xlsx_watermark(args.inspect_watermark)
        if report["verified"]:
            print("[PASS] WATERMARK VERIFIED: AUTHENTIC G-FLOW COMPILATION")
            print(json.dumps(report, indent=2))
            return 0
        print("[FAIL] WATERMARK VERIFICATION FAILED:", file=sys.stderr)
        for werr in report["errors"]:
            print(f"  - {werr}", file=sys.stderr)
        print(json.dumps(report, indent=2))
        return 1

    passed, errors = verify_repository(args.repo_dir)
    if passed:
        bm = json.loads((Path(args.repo_dir).resolve() / "benchmark_manifest.json").read_text("utf-8"))
        n_studies = len(bm.get("studies", []))
        print(
            f"[PASS] Verified 100% cryptographic, structural, Dual-Canvas SVG/PDF, Dual-Layer OpenXML Watermark, "
            f"and Zero-IP integrity across {n_studies} studies ({n_studies * 11} study files)."
        )
        return 0

    print(f"[FAIL] Integrity verification failed with {len(errors)} error(s):", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
