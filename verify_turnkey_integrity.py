#!/usr/bin/env python3
"""
Standalone Zero-Dependency Turnkey Benchmark Integrity Auditor
==============================================================
Cryptographically verifies SHA-256 digests, namespace-agnostic CDISC ODM v1.3.2 &
Veeva Vault CDMS XML structures, TransCelerate USDM v3.0 JSON schemas, OpenXML `.xlsx`
workbooks (5-Pass Medidata Rave ALS & Postfix RPN Stack Machine + 21 CFR Part 11
Provenance Matrix), Dual-Canvas Playwright vector diagrams (`canvas_standard.svg`/`.pdf`
vs. `canvas_mindmap.svg`/`.pdf`), and Zero-IP repository hygiene using ONLY the Python 3
Standard Library.

Usage:
    python3 verify_turnkey_integrity.py [--repo-dir .] [--validate-rave-als [PATH]]
    python3 verify_turnkey_integrity.py --inspect-watermark studies/NCT01631552/exports/rave_als.xlsx
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
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


def _xml_local_name(tag: str) -> str:
    return local_name(tag)


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


# ---------------------------------------------------------------------------
# 100% Python-Stdlib 5-Pass Rave ALS & Postfix RPN Validator + ODM Recompiler
# ---------------------------------------------------------------------------

REQUIRED_RAVE_ALS_SHEETS: Tuple[str, ...] = (
    "Draft",
    "Forms",
    "Fields",
    "Folders",
    "Matrices",
    "DataDictionaries",
    "Derivations",
    "EditChecks",
    "CheckSteps",
    "CheckActions",
)

REQUIRED_RAVE_ALS_COLUMNS: Dict[str, Tuple[str, ...]] = {
    "Draft": ("ProjectName", "DraftName", "Active"),
    "Forms": ("FormOID", "FormName", "Ordinal", "DraftFormActive"),
    "Fields": (
        "FormOID",
        "FieldOID",
        "Ordinal",
        "DraftFieldName",
        "VariableFormat",
        "ControlType",
        "DataDictionaryName",
    ),
    "Folders": ("FolderOID", "FolderName", "Ordinal", "DraftFolderActive"),
    "Matrices": ("MatrixName", "FolderOID", "FormOID", "DraftFormActive"),
    "DataDictionaries": ("DataDictionaryName", "CodedValue", "Ordinal", "UserDataString"),
    "Derivations": (
        "DerivationName",
        "FormOID",
        "FieldOID",
        "VariableFormat",
        "Ordinal",
        "Active",
        "Expression",
    ),
    "EditChecks": ("EditCheckName", "CheckActive", "DraftEditCheckActive"),
    "CheckSteps": (
        "EditCheckName",
        "StepNumber",
        "FormOID",
        "FieldOID",
        "VariableFormat",
        "CheckValue",
        "CheckOperator",
        "LogicalOperator",
        "RecordPosition",
    ),
    "CheckActions": (
        "EditCheckName",
        "ActionType",
        "FormOID",
        "FieldOID",
        "Message",
        "ActionNumber",
    ),
}

FORBIDDEN_ALS_PROVENANCE_COLUMNS: Tuple[str, ...] = (
    "SourceGrounding",
    "BoundingBox",
    "SourceQuote",
    "CharInterval",
    "DocumentHash",
    "GroundingType",
)

RAVE_RESERVED_AUX_SHEETS = {
    "codelists",
    "unitdictionaries",
    "labsettings",
    "customfunctions",
    "translations",
    "checks",
    "actions",
    "steps",
    "study",
    "project",
}

VALID_RAVE_CONTROL_TYPES = {
    "Text",
    "LongText",
    "Radio",
    "DropDownList",
    "CheckBox",
    "DateTime",
    "SearchList",
    "DynamicSearchList",
    "FileUpload",
    "Signature",
}
CHOICE_RAVE_CONTROL_TYPES = {"Radio", "DropDownList", "CheckBox"}
UNARY_RAVE_CHECK_OPERATORS = {
    "IsEmpty",
    "IsNotEmpty",
    "IsDirty",
    "IsNew",
    "IsActive",
    "IsFutureDate",
    "IsPresent",
    "NotExist",
}
BINARY_RAVE_CHECK_OPERATORS = {
    "IsEqualTo",
    "IsNotEqualTo",
    "IsLessThan",
    "IsLessThanOrEqualTo",
    "IsGreaterThan",
    "IsGreaterThanOrEqualTo",
    "Contains",
    "StartsWith",
}
UNARY_RAVE_LOGICAL_OPERATORS = {"NOT"}
BINARY_RAVE_LOGICAL_OPERATORS = {"AND", "OR", "XOR"}

_ALS_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_ALS_CELL_REF_COL_RE = re.compile(r"^([A-Za-z]+)")
_ALS_DATETIME_MASK_RE = re.compile(
    r"^(?:(?:dd|UN|uu)[-/](?:MMM|MM|UNK)[-/])?yyyy(?:\s+HH:MM(?::SS)?)?$"
    r"|^MMM[-/]yyyy$"
    r"|^HH:MM(?::SS)?$"
)
_ALS_TEXT_FMT_RE = re.compile(r"^\$[1-9]\d{0,4}$")
_ALS_INT_FMT_RE = re.compile(r"^[1-9]\d?$")
_ALS_FLOAT_FMT_RE = re.compile(r"^[1-9]\d?\.[1-9]\d?$")


def _col_letters_to_index(cell_ref: str) -> Optional[int]:
    m = _ALS_CELL_REF_COL_RE.match(cell_ref or "")
    if not m:
        return None
    col_idx = 0
    for ch in m.group(1).upper():
        col_idx = col_idx * 26 + (ord(ch) - ord("A") + 1)
    return col_idx - 1


def parse_openxml_workbook_bytes(xlsx_bytes: bytes) -> Dict[str, Any]:
    """
    100% Python-stdlib OpenXML `.xlsx` parser resolving `xl/sharedStrings.xml`, `inlineStr`,
    numeric/boolean `<v>` cells, `activeTab`, sheet `state`, and `<c r="C5">` column letters.
    """
    parse_errors: List[str] = []
    sheets_meta: List[Dict[str, Any]] = []
    sheet_by_name: Dict[str, Dict[str, Any]] = {}
    active_tab = "0"

    if not xlsx_bytes or not zipfile.is_zipfile(io.BytesIO(xlsx_bytes)):
        return {
            "active_tab": active_tab,
            "sheets": sheets_meta,
            "sheet_by_name": sheet_by_name,
            "parse_errors": ["Input bytes do not form a valid OpenXML ZIP archive."],
        }

    try:
        with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as zf:
            names = set(zf.namelist())
            if "xl/workbook.xml" not in names:
                return {
                    "active_tab": active_tab,
                    "sheets": sheets_meta,
                    "sheet_by_name": sheet_by_name,
                    "parse_errors": ["Workbook archive missing 'xl/workbook.xml'."],
                }

            shared_strings: List[str] = []
            if "xl/sharedStrings.xml" in names:
                sst_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for si_el in sst_root:
                    if _xml_local_name(si_el.tag) == "si":
                        shared_strings.append(
                            "".join(
                                (t_el.text or "")
                                for t_el in si_el.iter()
                                if _xml_local_name(t_el.tag) == "t"
                            )
                        )

            rel_map: Dict[str, str] = {}
            if "xl/_rels/workbook.xml.rels" in names:
                rels_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
                for rel_el in rels_root:
                    if _xml_local_name(rel_el.tag) == "Relationship":
                        rid = rel_el.attrib.get("Id", "")
                        rtarget = rel_el.attrib.get("Target", "")
                        if rid and rtarget:
                            rel_map[rid] = rtarget

            wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
            for el in wb_root.iter():
                if _xml_local_name(el.tag) == "workbookView":
                    active_tab = el.attrib.get("activeTab", "0")
                    break

            raw_sheets = [el for el in wb_root.iter() if _xml_local_name(el.tag) == "sheet"]
            for idx, sh_el in enumerate(raw_sheets):
                sh_name = sh_el.attrib.get("name", "")
                sh_state = sh_el.attrib.get("state", "visible")
                rid_val = ""
                for attr_k, attr_v in sh_el.attrib.items():
                    if _xml_local_name(attr_k) == "id":
                        rid_val = attr_v
                        break
                raw_target = rel_map.get(rid_val, "")
                norm_target = raw_target.lstrip("/")
                if norm_target and not norm_target.startswith("xl/") and f"xl/{norm_target}" in names:
                    norm_target = f"xl/{norm_target}"

                headers: List[str] = []
                header_by_col: Dict[int, str] = {}
                rows: List[Dict[str, str]] = []
                row_numbers: List[int] = []

                if not norm_target or norm_target not in names:
                    parse_errors.append(
                        f"Worksheet '{sh_name}' XML target '{raw_target}' (r:id='{rid_val}') missing from archive."
                    )
                else:
                    ws_root = ET.fromstring(zf.read(norm_target))
                    header_parsed = False
                    fallback_row_num = 0
                    for row_el in ws_root.iter():
                        if _xml_local_name(row_el.tag) != "row":
                            continue
                        fallback_row_num += 1
                        r_attr = row_el.attrib.get("r", "")
                        excel_row_num = int(r_attr) if r_attr.isdigit() else fallback_row_num

                        cell_map: Dict[int, str] = {}
                        next_col = 0
                        for c_el in row_el:
                            if _xml_local_name(c_el.tag) != "c":
                                continue
                            c_ref = c_el.attrib.get("r", "")
                            col_idx = _col_letters_to_index(c_ref)
                            if col_idx is None:
                                col_idx = next_col
                            next_col = col_idx + 1

                            c_type = c_el.attrib.get("t", "")
                            if c_type == "inlineStr":
                                raw_val = "".join(
                                    (t_el.text or "")
                                    for t_el in c_el.iter()
                                    if _xml_local_name(t_el.tag) == "t"
                                )
                            elif c_type == "s":
                                v_nodes = [ch for ch in c_el if _xml_local_name(ch.tag) == "v"]
                                idx_str = (v_nodes[0].text or "").strip() if v_nodes else ""
                                raw_val = (
                                    shared_strings[int(idx_str)]
                                    if idx_str.isdigit() and int(idx_str) < len(shared_strings)
                                    else ""
                                )
                            elif c_type == "b":
                                v_nodes = [ch for ch in c_el if _xml_local_name(ch.tag) == "v"]
                                b_txt = (v_nodes[0].text or "").strip() if v_nodes else "0"
                                raw_val = "TRUE" if b_txt == "1" else "FALSE"
                            else:
                                v_nodes = [ch for ch in c_el if _xml_local_name(ch.tag) == "v"]
                                raw_val = (v_nodes[0].text or "") if v_nodes else ""

                            cell_map[col_idx] = raw_val

                        if not header_parsed:
                            header_parsed = True
                            if cell_map:
                                max_col = max(cell_map.keys())
                                for c_i in range(max_col + 1):
                                    h_name = cell_map.get(c_i, "").strip()
                                    if h_name:
                                        header_by_col[c_i] = h_name
                                        headers.append(h_name)
                        else:
                            if not header_by_col:
                                continue
                            row_dict = {
                                h_name: cell_map.get(c_i, "").strip(" ")
                                for c_i, h_name in header_by_col.items()
                            }
                            if any(v != "" for v in row_dict.values()):
                                rows.append(row_dict)
                                row_numbers.append(excel_row_num)

                sh_info = {
                    "index": idx,
                    "name": sh_name,
                    "state": sh_state,
                    "target": norm_target,
                    "headers": headers,
                    "rows": rows,
                    "row_numbers": row_numbers,
                }
                sheets_meta.append(sh_info)
                if sh_name not in sheet_by_name:
                    sheet_by_name[sh_name] = sh_info
                else:
                    parse_errors.append(f"Duplicate worksheet name '{sh_name}' in workbook.xml.")
    except Exception as exc:
        parse_errors.append(f"OpenXML workbook parse failure: {exc}")

    return {
        "active_tab": active_tab,
        "sheets": sheets_meta,
        "sheet_by_name": sheet_by_name,
        "parse_errors": parse_errors,
    }


def is_rave_als_workbook(parsed_wb: Dict[str, Any]) -> bool:
    sbn = parsed_wb.get("sheet_by_name", {})
    if "Fields" not in sbn or "CheckSteps" not in sbn:
        return False
    cs_headers = set(sbn["CheckSteps"].get("headers", ()))
    return "CheckOperator" in cs_headers


def _als_positive_int(raw: str) -> Optional[int]:
    txt = (raw or "").strip()
    if not txt:
        return None
    if txt.isdigit():
        val = int(txt)
        return val if val > 0 else None
    try:
        fval = float(txt)
        if fval.is_integer() and int(fval) > 0:
            return int(fval)
    except ValueError:
        pass
    return None


def _is_valid_als_scalar_format(vfmt: str) -> bool:
    return bool(
        _ALS_TEXT_FMT_RE.match(vfmt)
        or _ALS_INT_FMT_RE.match(vfmt)
        or _ALS_FLOAT_FMT_RE.match(vfmt)
    )


def validate_rave_als_parsed(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes all 5 offline Medidata Rave Architect Loader (`ALS`) & Postfix RPN Stack passes
    using only the Python 3 Standard Library.
    """
    p1_errors: List[str] = list(parsed.get("parse_errors", []))
    p2_errors: List[str] = []
    p3_errors: List[str] = []
    p4_errors: List[str] = []
    p5_errors: List[str] = []
    rpn_traces: Dict[str, List[int]] = {}

    sheets: List[Dict[str, Any]] = parsed.get("sheets", [])
    sbn: Dict[str, Dict[str, Any]] = parsed.get("sheet_by_name", {})
    active_tab = str(parsed.get("active_tab", "0"))

    # Pass 1: Worksheet, Column Contract & veryHidden Watermark Non-Interference
    if active_tab != "0":
        p1_errors.append(f"[Pass 1] Workbook activeTab must be '0' ('Draft'), got activeTab='{active_tab}'.")
    if sheets:
        first_sheet = sheets[0]
        if first_sheet["name"] != "Draft":
            p1_errors.append(f"[Pass 1] Primary tab at index 0 must be 'Draft', got '{first_sheet['name']}'.")
        if first_sheet["state"] != "visible":
            p1_errors.append(f"[Pass 1] 'Draft' worksheet must be 'visible', got state='{first_sheet['state']}'.")

    required_set = set(REQUIRED_RAVE_ALS_SHEETS)
    required_lower_map = {s.lower(): s for s in REQUIRED_RAVE_ALS_SHEETS}
    seen_lower: Dict[str, str] = {}
    for sh in sheets:
        sname = sh["name"]
        slower = sname.lower()
        if slower in seen_lower and seen_lower[slower] != sname:
            p1_errors.append(f"[Pass 1] Case-insensitive worksheet collision between '{seen_lower[slower]}' and '{sname}'.")
        seen_lower[slower] = sname
        if sname in required_set:
            if sh["state"] != "visible":
                p1_errors.append(f"[Pass 1] Standard Rave ALS worksheet '{sname}' must be visible, got state='{sh['state']}'.")
        elif sname == WATERMARK_SHEET_NAME:
            if sh["state"] != "veryHidden":
                p1_errors.append(
                    f"[Pass 1] Auxiliary forensic watermark sheet '{WATERMARK_SHEET_NAME}' must have state='veryHidden', got '{sh['state']}'."
                )
            if sh["index"] != len(sheets) - 1:
                p1_errors.append(
                    f"[Pass 1] Auxiliary forensic watermark sheet '{WATERMARK_SHEET_NAME}' must be at index {len(sheets) - 1}, got {sh['index']}."
                )
        else:
            if slower.startswith("matrix"):
                p1_errors.append(f"[Pass 1] Illegal 'Matrix*' worksheet '{sname}' detected.")
            elif slower in RAVE_RESERVED_AUX_SHEETS or slower in required_lower_map:
                p1_errors.append(f"[Pass 1] Reserved Rave Architect worksheet collision on '{sname}'.")
            else:
                p1_errors.append(f"[Pass 1] Non-standard worksheet '{sname}' is not permitted in Rave ALS workbook.")

    for req_sheet in REQUIRED_RAVE_ALS_SHEETS:
        sh = sbn.get(req_sheet)
        if sh is None:
            p1_errors.append(f"[Pass 1] Missing required standard Rave ALS worksheet '{req_sheet}'.")
            continue
        hdr_set = set(sh["headers"])
        missing_cols = [c for c in REQUIRED_RAVE_ALS_COLUMNS[req_sheet] if c not in hdr_set]
        if missing_cols:
            p1_errors.append(f"[Pass 1] Worksheet '{req_sheet}' missing required columns: {missing_cols}.")
        leaked_cols = [c for c in FORBIDDEN_ALS_PROVENANCE_COLUMNS if c in hdr_set]
        if leaked_cols:
            p1_errors.append(f"[Pass 1] Worksheet '{req_sheet}' contains forbidden provenance columns: {leaked_cols}.")

    draft_sh = sbn.get("Draft")
    if draft_sh is not None:
        if len(draft_sh["rows"]) < 1:
            p1_errors.append("[Pass 1] 'Draft' worksheet must contain at least 1 row.")
        else:
            d0 = draft_sh["rows"][0]
            if not d0.get("ProjectName") or not d0.get("DraftName"):
                p1_errors.append("[Pass 1] 'Draft' row 1 must populate non-empty 'ProjectName' and 'DraftName'.")

    # Pass 2: OID Hygiene & Primary Key Uniqueness
    def _check_pk(sheet_name: str, col_name: str) -> None:
        seen = set()
        sh = sbn.get(sheet_name)
        if not sh:
            return
        for idx, row in enumerate(sh["rows"]):
            rnum = sh["row_numbers"][idx]
            val = row.get(col_name, "")
            if not val:
                p2_errors.append(f"[Pass 2] {sheet_name} row {rnum}: '{col_name}' is empty.")
                continue
            if _ALS_CONTROL_CHAR_RE.search(val):
                p2_errors.append(f"[Pass 2] {sheet_name} row {rnum}: '{col_name}' contains illegal control character: {val!r}.")
            if val in seen:
                p2_errors.append(f"[Pass 2] {sheet_name} row {rnum}: Duplicate {col_name} '{val}'.")
            seen.add(val)

    _check_pk("Folders", "FolderOID")
    _check_pk("Forms", "FormOID")
    _check_pk("EditChecks", "EditCheckName")
    _check_pk("Derivations", "DerivationName")

    fields_sh = sbn.get("Fields", {"rows": [], "row_numbers": []})
    seen_fields = set()
    for idx, row in enumerate(fields_sh["rows"]):
        rnum = fields_sh["row_numbers"][idx]
        f_oid = row.get("FormOID", "")
        fld_oid = row.get("FieldOID", "")
        if not f_oid or not fld_oid:
            p2_errors.append(f"[Pass 2] Fields row {rnum}: FormOID ('{f_oid}') and FieldOID ('{fld_oid}') must both be non-empty.")
            continue
        if _ALS_CONTROL_CHAR_RE.search(f_oid) or _ALS_CONTROL_CHAR_RE.search(fld_oid):
            p2_errors.append(f"[Pass 2] Fields row {rnum}: FormOID/FieldOID contains illegal control character: ({f_oid!r}, {fld_oid!r}).")
        pair = (f_oid, fld_oid)
        if pair in seen_fields:
            p2_errors.append(f"[Pass 2] Fields row {rnum}: Duplicate (FormOID, FieldOID) pair {pair}.")
        seen_fields.add(pair)

    dd_sh = sbn.get("DataDictionaries", {"rows": [], "row_numbers": []})
    seen_dd = set()
    for idx, row in enumerate(dd_sh["rows"]):
        rnum = dd_sh["row_numbers"][idx]
        dd_name = row.get("DataDictionaryName", "")
        coded = row.get("CodedValue", "")
        if not dd_name or coded == "":
            p2_errors.append(f"[Pass 2] DataDictionaries row {rnum}: DataDictionaryName and CodedValue must be non-empty.")
            continue
        if _ALS_CONTROL_CHAR_RE.search(dd_name) or _ALS_CONTROL_CHAR_RE.search(coded):
            p2_errors.append(f"[Pass 2] DataDictionaries row {rnum}: Control character in ({dd_name!r}, {coded!r}).")
        key = (dd_name, coded)
        if key in seen_dd:
            p2_errors.append(f"[Pass 2] DataDictionaries row {rnum}: Duplicate (DataDictionaryName, CodedValue) {key}.")
        seen_dd.add(key)

    # Pass 3: Cross-Sheet Relational Foreign-Key Integrity
    known_forms = {r["FormOID"] for r in sbn.get("Forms", {}).get("rows", []) if r.get("FormOID")}
    known_folders = {r["FolderOID"] for r in sbn.get("Folders", {}).get("rows", []) if r.get("FolderOID")}
    known_dicts = {r["DataDictionaryName"] for r in dd_sh["rows"] if r.get("DataDictionaryName")}
    known_fields = {(r["FormOID"], r["FieldOID"]) for r in fields_sh["rows"] if r.get("FormOID") and r.get("FieldOID")}
    known_checks = {r["EditCheckName"] for r in sbn.get("EditChecks", {}).get("rows", []) if r.get("EditCheckName")}

    for idx, row in enumerate(fields_sh["rows"]):
        rnum = fields_sh["row_numbers"][idx]
        f_oid = row.get("FormOID", "")
        fld_oid = row.get("FieldOID", "")
        dd_name = row.get("DataDictionaryName", "")
        if f_oid and f_oid not in known_forms:
            p3_errors.append(f"[Pass 3] Fields row {rnum} ('{fld_oid}'): FormOID '{f_oid}' does not exist in Forms.")
        if dd_name and dd_name not in known_dicts:
            p3_errors.append(f"[Pass 3] Fields row {rnum} ('{f_oid}.{fld_oid}'): DataDictionaryName '{dd_name}' does not exist in DataDictionaries.")

    matrices_sh = sbn.get("Matrices", {"rows": [], "row_numbers": []})
    for idx, row in enumerate(matrices_sh["rows"]):
        rnum = matrices_sh["row_numbers"][idx]
        fl_oid = row.get("FolderOID", "")
        fm_oid = row.get("FormOID", "")
        if fl_oid not in known_folders:
            p3_errors.append(f"[Pass 3] Matrices row {rnum}: FolderOID '{fl_oid}' does not exist in Folders.")
        if fm_oid not in known_forms:
            p3_errors.append(f"[Pass 3] Matrices row {rnum}: FormOID '{fm_oid}' does not exist in Forms.")

    derivs_sh = sbn.get("Derivations", {"rows": [], "row_numbers": []})
    for idx, row in enumerate(derivs_sh["rows"]):
        rnum = derivs_sh["row_numbers"][idx]
        d_name = row.get("DerivationName", "")
        f_oid = row.get("FormOID", "")
        fld_oid = row.get("FieldOID", "")
        if not f_oid or not fld_oid or (f_oid, fld_oid) not in known_fields:
            p3_errors.append(f"[Pass 3] Derivations row {rnum} ('{d_name}'): target ({f_oid!r}, {fld_oid!r}) does not exist in Fields.")

    steps_sh = sbn.get("CheckSteps", {"rows": [], "row_numbers": []})
    checks_with_steps = set()
    for idx, row in enumerate(steps_sh["rows"]):
        rnum = steps_sh["row_numbers"][idx]
        ec_name = row.get("EditCheckName", "")
        f_oid = row.get("FormOID", "")
        fld_oid = row.get("FieldOID", "")
        if ec_name not in known_checks:
            p3_errors.append(f"[Pass 3] CheckSteps row {rnum}: EditCheckName '{ec_name}' does not exist in EditChecks.")
        else:
            checks_with_steps.add(ec_name)
        if f_oid or fld_oid:
            if not f_oid or not fld_oid or (f_oid, fld_oid) not in known_fields:
                p3_errors.append(f"[Pass 3] CheckSteps row {rnum} ('{ec_name}'): field reference ({f_oid!r}, {fld_oid!r}) does not exist in Fields.")

    actions_sh = sbn.get("CheckActions", {"rows": [], "row_numbers": []})
    checks_with_actions = set()
    for idx, row in enumerate(actions_sh["rows"]):
        rnum = actions_sh["row_numbers"][idx]
        ec_name = row.get("EditCheckName", "")
        f_oid = row.get("FormOID", "")
        fld_oid = row.get("FieldOID", "")
        if ec_name not in known_checks:
            p3_errors.append(f"[Pass 3] CheckActions row {rnum}: EditCheckName '{ec_name}' does not exist in EditChecks.")
        else:
            checks_with_actions.add(ec_name)
        if not f_oid or not fld_oid or (f_oid, fld_oid) not in known_fields:
            p3_errors.append(f"[Pass 3] CheckActions row {rnum} ('{ec_name}'): action target ({f_oid!r}, {fld_oid!r}) does not exist in Fields.")

    for ec_name in sorted(known_checks):
        if ec_name not in checks_with_steps:
            p3_errors.append(f"[Pass 3] EditCheck '{ec_name}' has zero CheckSteps rows.")
        if ec_name not in checks_with_actions:
            p3_errors.append(f"[Pass 3] EditCheck '{ec_name}' has zero CheckActions rows.")

    # Pass 4: ControlType <-> VariableFormat <-> DataDictionary Compatibility
    for idx, row in enumerate(fields_sh["rows"]):
        rnum = fields_sh["row_numbers"][idx]
        f_oid = row.get("FormOID", "")
        fld_oid = row.get("FieldOID", "")
        ctrl = row.get("ControlType", "")
        vfmt = row.get("VariableFormat", "")
        dd_name = row.get("DataDictionaryName", "")
        if ctrl not in VALID_RAVE_CONTROL_TYPES:
            p4_errors.append(f"[Pass 4] Fields row {rnum} ('{f_oid}.{fld_oid}'): unsupported Rave ControlType '{ctrl}'.")
            continue
        if ctrl in CHOICE_RAVE_CONTROL_TYPES:
            if not dd_name:
                p4_errors.append(f"[Pass 4] Fields row {rnum} ('{f_oid}.{fld_oid}'): ControlType '{ctrl}' requires non-empty DataDictionaryName.")
            if not _is_valid_als_scalar_format(vfmt):
                p4_errors.append(f"[Pass 4] Fields row {rnum} ('{f_oid}.{fld_oid}'): ControlType '{ctrl}' has invalid VariableFormat '{vfmt}'.")
        elif ctrl == "DateTime":
            if dd_name:
                p4_errors.append(f"[Pass 4] Fields row {rnum} ('{f_oid}.{fld_oid}'): ControlType 'DateTime' cannot bind DataDictionaryName '{dd_name}'.")
            if not _ALS_DATETIME_MASK_RE.match(vfmt):
                p4_errors.append(f"[Pass 4] Fields row {rnum} ('{f_oid}.{fld_oid}'): ControlType 'DateTime' requires date/time mask, got '{vfmt}'.")
        elif ctrl in {"Text", "LongText"}:
            if dd_name:
                p4_errors.append(f"[Pass 4] Fields row {rnum} ('{f_oid}.{fld_oid}'): ControlType '{ctrl}' cannot bind DataDictionaryName '{dd_name}'.")
            if _ALS_DATETIME_MASK_RE.match(vfmt) or not _is_valid_als_scalar_format(vfmt):
                p4_errors.append(f"[Pass 4] Fields row {rnum} ('{f_oid}.{fld_oid}'): ControlType '{ctrl}' has incompatible VariableFormat '{vfmt}'.")
        else:
            if vfmt and (_ALS_DATETIME_MASK_RE.match(vfmt) or not _is_valid_als_scalar_format(vfmt)):
                p4_errors.append(f"[Pass 4] Fields row {rnum} ('{f_oid}.{fld_oid}'): ControlType '{ctrl}' has invalid VariableFormat '{vfmt}'.")

    # Pass 5: Postfix Reverse Polish Notation (RPN) Stack Machine Simulation
    grouped: Dict[str, List[Tuple[int, int, Dict[str, str]]]] = {}
    for idx, row in enumerate(steps_sh["rows"]):
        rnum = steps_sh["row_numbers"][idx]
        ec_name = row.get("EditCheckName", "")
        step_num_raw = row.get("StepNumber", "")
        step_num = _als_positive_int(step_num_raw)
        if step_num is None:
            p5_errors.append(f"[Pass 5] CheckSteps row {rnum} ('{ec_name}'): StepNumber '{step_num_raw}' must be a positive integer.")
            continue
        grouped.setdefault(ec_name, []).append((step_num, rnum, row))

    for ec_name, items in grouped.items():
        items_sorted = sorted(items, key=lambda t: t[0])
        expected_nums = list(range(1, len(items_sorted) + 1))
        actual_nums = [t[0] for t in items_sorted]
        if actual_nums != expected_nums:
            p5_errors.append(
                f"[Pass 5] EditCheck '{ec_name}': StepNumber sequence {actual_nums} must be consecutive 1..{len(items_sorted)}."
            )

        stack_depth = 0
        trace: List[int] = []
        aborted = False
        for step_num, rnum, row in items_sorted:
            f_oid = row.get("FormOID", "")
            fld_oid = row.get("FieldOID", "")
            chk_val = row.get("CheckValue", "")
            chk_op = row.get("CheckOperator", "")
            log_op = row.get("LogicalOperator", "")

            has_field = bool(f_oid or fld_oid)
            has_const = chk_val != ""

            if chk_op.lower() == "customfunction":
                p5_errors.append(f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): forbidden 'CustomFunction' placeholder.")
                aborted = True
                continue
            if chk_op and log_op:
                p5_errors.append(
                    f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): combined CheckOperator '{chk_op}' and LogicalOperator '{log_op}' on same row."
                )
                aborted = True
                continue
            if has_field and has_const:
                p5_errors.append(
                    f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): cannot push both FieldOID '{fld_oid}' and CheckValue '{chk_val}'."
                )
                aborted = True
                continue
            if (has_field or has_const) and (chk_op or log_op):
                p5_errors.append(
                    f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): combined operand push and operator ('{chk_op or log_op}') on same row."
                )
                aborted = True
                continue
            if not has_field and not has_const and not chk_op and not log_op:
                p5_errors.append(f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): empty no-op CheckStep row.")
                aborted = True
                continue

            if has_field or has_const:
                stack_depth += 1
            elif chk_op:
                if chk_op in UNARY_RAVE_CHECK_OPERATORS:
                    if stack_depth < 1:
                        p5_errors.append(
                            f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): RPN stack underflow on unary CheckOperator '{chk_op}' (stack_depth={stack_depth} < 1)."
                        )
                        aborted = True
                        continue
                elif chk_op in BINARY_RAVE_CHECK_OPERATORS:
                    if stack_depth < 2:
                        p5_errors.append(
                            f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): RPN stack underflow on binary CheckOperator '{chk_op}' (stack_depth={stack_depth} < 2)."
                        )
                        aborted = True
                        continue
                    stack_depth -= 1
                else:
                    p5_errors.append(f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): unknown Rave CheckOperator '{chk_op}'.")
                    aborted = True
                    continue
            elif log_op:
                if log_op in UNARY_RAVE_LOGICAL_OPERATORS:
                    if stack_depth < 1:
                        p5_errors.append(
                            f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): RPN stack underflow on unary LogicalOperator '{log_op}' (stack_depth={stack_depth} < 1)."
                        )
                        aborted = True
                        continue
                elif log_op in BINARY_RAVE_LOGICAL_OPERATORS:
                    if stack_depth < 2:
                        p5_errors.append(
                            f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): RPN stack underflow on LogicalOperator '{log_op}' (stack_depth={stack_depth} < 2)."
                        )
                        aborted = True
                        continue
                    stack_depth -= 1
                else:
                    p5_errors.append(f"[Pass 5] EditCheck '{ec_name}' Step {step_num} (row {rnum}): unknown Rave LogicalOperator '{log_op}'.")
                    aborted = True
                    continue

            trace.append(stack_depth)

        rpn_traces[ec_name] = trace
        if not aborted and stack_depth != 1:
            p5_errors.append(f"[Pass 5] EditCheck '{ec_name}' terminated with final_stack_depth={stack_depth} (expected 1).")

    all_errors = p1_errors + p2_errors + p3_errors + p4_errors + p5_errors
    return {
        "is_valid": len(all_errors) == 0,
        "errors": all_errors,
        "sheet_row_counts": {sh["name"]: len(sh["rows"]) for sh in sheets},
        "rpn_stack_traces": rpn_traces,
        "pass_summary": {
            "pass_1": len(p1_errors) == 0,
            "pass_2": len(p2_errors) == 0,
            "pass_3": len(p3_errors) == 0,
            "pass_4": len(p4_errors) == 0,
            "pass_5": len(p5_errors) == 0,
        },
    }


def _check_openxml_xlsx(
    xlsx_path: Path,
    label: str,
    errors: List[str],
    expected_nct_id: Optional[str] = None,
    expected_design_id: Optional[str] = None,
    expected_proto_sha: Optional[str] = None,
    required_non_empty_sheets: Tuple[str, ...] = (),
    force_validate_rave_als: bool = False,
    require_watermark: bool = True,
) -> None:
    xlsx_path = Path(xlsx_path)
    if not zipfile.is_zipfile(xlsx_path):
        errors.append(f"{label}: '{xlsx_path}' is not a valid OpenXML ZIP archive.")
        return

    parsed = parse_openxml_workbook_bytes(xlsx_path.read_bytes())
    if parsed["parse_errors"]:
        for perr in parsed["parse_errors"]:
            errors.append(f"{label}: {perr}")
        return

    visible_sheets = [
        s for s in parsed["sheets"] if s["name"] != WATERMARK_SHEET_NAME
    ]
    if not visible_sheets:
        errors.append(f"{label}: '{xlsx_path}' workbook contains zero data worksheet definitions.")
    sheet_by_name = {s["name"]: s for s in visible_sheets}
    for req_sheet in required_non_empty_sheets:
        sh_info = sheet_by_name.get(req_sheet)
        if sh_info is None:
            errors.append(f"{label}: missing required worksheet '{req_sheet}'.")
            continue
        if len(sh_info["rows"]) < 1:
            errors.append(
                f"{label}: worksheet '{req_sheet}' contains zero compiled data rows."
            )

    if force_validate_rave_als or is_rave_als_workbook(parsed):
        als_res = validate_rave_als_parsed(parsed)
        if not als_res["is_valid"]:
            for aerr in als_res["errors"]:
                errors.append(f"{label}: {aerr}")

    if not require_watermark:
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
    for req_tag in ("Study", "MetaDataVersion", "FormDef", "ItemDef", "ConditionDef"):
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
        and bool(found_tags & {"Rule", "RuleDef", "EditCheck"})
    )
    is_odm_compat = (
        rname == "ODM"
        and {"Study", "MetaDataVersion", "FormDef", "ItemDef", "ConditionDef"}.issubset(found_tags)
    )
    if not (is_veeva_native or is_odm_compat):
        errors.append(
            f"[{nct_id}] '{xml_path.name}' missing required Veeva CDMS Forms/Items/Rules or ODM ConditionDef definitions."
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


def verify_repository(
    repo_dir: Path, force_validate_rave_als: bool = False
) -> Tuple[bool, List[str]]:
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

        # 1b. Verify 9 sibling artifacts & non-zero EditCheck telemetry in studies/<NCT_ID>/metadata/compilation_manifest.json
        st_ec_count = int((st.get("telemetry") or {}).get("edit_check_count") or 0)
        if st_ec_count <= 0:
            errors.append(
                f"[{nct_id}] benchmark_manifest.json telemetry.edit_check_count must be > 0, got {st_ec_count}."
            )
        cm_path = study_dir / "metadata" / "compilation_manifest.json"
        if cm_path.is_file():
            try:
                cm = json.loads(cm_path.read_text(encoding="utf-8"))
                cm_ec_count = int((cm.get("telemetry") or {}).get("edit_check_count") or 0)
                if cm_ec_count <= 0:
                    errors.append(
                        f"[{nct_id}] compilation_manifest.json telemetry.edit_check_count must be > 0, got {cm_ec_count}."
                    )
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
                required_non_empty_sheets=("EditChecks", "CheckSteps"),
                force_validate_rave_als=force_validate_rave_als,
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
                required_non_empty_sheets=("EditCheck_Provenance",),
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
    parser.add_argument(
        "--validate-rave-als",
        nargs="?",
        const="__ALL__",
        default=None,
        help="Force 5-Pass Medidata Rave ALS & Postfix RPN Stack validation on all repo studies or a single .xlsx file.",
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

    if args.validate_rave_als is not None and args.validate_rave_als != "__ALL__":
        als_target = Path(args.validate_rave_als)
        if not als_target.is_file():
            print(f"[FAIL] Rave ALS file does not exist: '{als_target}'.", file=sys.stderr)
            return 1
        parsed = parse_openxml_workbook_bytes(als_target.read_bytes())
        als_rep = validate_rave_als_parsed(parsed)
        if als_rep["is_valid"]:
            print(
                f"[PASS] RAVE ALS 5-PASS & RPN STACK VERIFIED: '{als_target}' "
                f"(simulated_edit_checks={len(als_rep['rpn_stack_traces'])}, 0 errors)"
            )
            print(json.dumps(als_rep, indent=2))
            return 0
        print(f"[FAIL] RAVE ALS 5-PASS VALIDATION FAILED ({len(als_rep['errors'])} error(s)):", file=sys.stderr)
        for aerr in als_rep["errors"]:
            print(f"  - {aerr}", file=sys.stderr)
        return 1

    passed, errors = verify_repository(
        args.repo_dir, force_validate_rave_als=(args.validate_rave_als == "__ALL__")
    )
    if passed:
        bm = json.loads((Path(args.repo_dir).resolve() / "benchmark_manifest.json").read_text("utf-8"))
        n_studies = len(bm.get("studies", []))
        print(
            f"[PASS] Verified 100% cryptographic, structural, 5-Pass Rave ALS & RPN Stack, Dual-Canvas SVG/PDF, "
            f"Dual-Layer OpenXML Watermark, and Zero-IP integrity across {n_studies} studies ({n_studies * 11} study files)."
        )
        return 0

    print(f"[FAIL] Integrity verification failed with {len(errors)} error(s):", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
