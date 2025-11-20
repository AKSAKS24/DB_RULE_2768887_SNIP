from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Tuple
import re

app = FastAPI(
    title="Rule 2768887 — VBRK/VBRP draft filter check",
    version="2.0",
)

# ---------------------------------------------------------------------------
# Regex to detect SELECT ... FROM ... INTO ...
# ---------------------------------------------------------------------------
SELECT_RE = re.compile(
    r"""(?P<full>
        SELECT\s+(?:SINGLE\s+)?                # SELECT or SELECT SINGLE
        (?P<fields>.+?)                        # everything up to FROM (fields)
        \s+FROM\s+(?P<from_clause>.*?)         # from clause
        (?=
            \s+(WHERE|INTO|ORDER|GROUP|HAVING|FOR\s+ALL\s+ENTRIES|$)
        )
        (?P<middle>.*?)
        (?:
            (?:INTO\s+TABLE\s+(?P<into_tab>[\w@()\->]+))
          | (?:INTO\s+(?P<into_wa>[\w@()\->]+))
        )
        (?P<tail>.*?)
    )\.""",
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Models (reference style: header + findings)
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None      # "MissingDraftFilter"
    severity: Optional[str] = None         # always "error"
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None          # line where issue occurs


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = None
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Given a match span (start, end), return the full line in which
    that match occurs (no extra lines).
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1  # right after '\n'

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


def extract_tables(from_clause: str) -> List[Dict[str, str]]:
    """
    Extract all tables (and aliases if present) used in FROM and all JOINs.
    Returns list of dicts with {table: 'VBRK', alias: 'B'}.
    """
    tables: List[Dict[str, str]] = []
    join_parts = re.split(r"\bJOIN\b", from_clause, flags=re.IGNORECASE)
    tbl_alias_re = re.compile(r"(\w+)(?:\s+(?:AS\s+)?(\w+))?", re.IGNORECASE)

    for join_part in join_parts:
        join_part = re.split(r"\bON\b", join_part, flags=re.IGNORECASE)[0]
        candidates = join_part.split(",")
        for candidate in candidates:
            cand = candidate.strip()
            if not cand:
                continue
            m = tbl_alias_re.match(cand)
            if m:
                table = (m.group(1) or "").upper()
                alias = (m.group(2) or m.group(1) or "").upper()
                if table:
                    tables.append({"table": table, "alias": alias})
    return tables


def find_selects(txt: str) -> List[Dict[str, Any]]:
    """
    Find all SELECTs on VBRK/VBRP (any join, any alias, any INTO).
    """
    out: List[Dict[str, Any]] = []
    for m in SELECT_RE.finditer(txt):
        from_clause = m.group("from_clause")
        tables = extract_tables(from_clause)
        is_vbrk_vbrp = [t for t in tables if t["table"] in ("VBRK", "VBRP")]
        if not is_vbrk_vbrp:
            continue

        out.append(
            {
                "text": m.group("full"),
                "tables": tables,
                "span": m.span(0),
            }
        )
    return out


# --- Draft filter helpers ----------------------------------------------------
def _has_draft_check(sel_stmt: str, alias: str) -> bool:
    """
    True if sel_stmt already has alias~draft = SPACE / ' ' / '' / abap_false etc.
    """
    pat = rf"{re.escape(alias)}\s*~\s*draft\s*=\s*(SPACE|' '|\"\"|''|abap_false|ABAP_FALSE)"
    return re.search(pat, sel_stmt, flags=re.IGNORECASE) is not None


def draft_filter_missing(sel_stmt: str, tables: List[Dict[str, str]]) -> bool:
    """
    Returns True if at least one VBRK/VBRP alias does NOT have a draft filter.
    """
    v_tables = [t for t in tables if t["table"] in ("VBRK", "VBRP")]
    if not v_tables:
        return False

    # If all relevant aliases already have draft filter, then nothing is missing
    if all(_has_draft_check(sel_stmt, t["alias"]) for t in v_tables):
        return False

    return True


# ---------------------------------------------------------------------------
# Core scanner (only reports; does NOT modify code)
# ---------------------------------------------------------------------------
def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    selects = find_selects(src)
    findings: List[Finding] = []

    base_start = unit.start_line or 0

    for sel in selects:
        sel_text = sel["text"]
        tables = sel["tables"]

        # Only report when draft filter is missing for at least one VBRK/VBRP alias
        if not draft_filter_missing(sel_text, tables):
            continue

        stmt_start, stmt_end = sel["span"]

        # Line within this block (1-based)
        line_in_block = src[:stmt_start].count("\n") + 1

        # Snippet = full line containing the SELECT
        snippet_line = get_line_snippet(src, stmt_start, stmt_end)
        snippet_line_count = snippet_line.count("\n") + 1  # usually 1

        # Absolute line numbers in full program
        starting_line_abs = base_start + line_in_block
        ending_line_abs = base_start + line_in_block + snippet_line_count

        table_list = ", ".join(
            [f"{t['table']} ({t['alias']})" for t in tables if t["table"] in ("VBRK", "VBRP")]
        )

        msg = "SELECT on VBRK/VBRP without draft filter per SAP Note 2768887."
        sug = (
            f"For this SELECT on {table_list}, add draft filter condition(s) "
            f"alias~draft = space for all VBRK/VBRP aliases involved."
        )

        finding = Finding(
            prog_name=unit.pgm_name,
            incl_name=unit.inc_name,
            types=unit.type,
            blockname=unit.name,
            starting_line=starting_line_abs,
            ending_line=ending_line_abs,
            issues_type="MissingDraftFilter",
            severity="error",
            message=msg,
            suggestion=sug,
            snippet=snippet_line.replace("\n", "\\n"),
        )
        findings.append(finding)

    out_unit = Unit(**unit.model_dump())
    out_unit.findings = findings if findings else None
    return out_unit


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def remediate_array(units: List[Unit] = Body(...)):
    results: List[Unit] = []
    for u in units:
        res = scan_unit(u)
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def remediate_single(unit: Unit = Body(...)):
    return scan_unit(unit)


@app.get("/health")
def health():
    return {"ok": True, "rule": 2768887, "version": "2.0"}
