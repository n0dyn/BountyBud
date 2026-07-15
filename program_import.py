#!/usr/bin/env python3
"""Parse bug bounty program scope CSV and guidelines for Mythos + BountyBud."""
from __future__ import annotations

import csv
import io
import json
import os
import re
from pathlib import Path
from typing import Any


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", name.strip().lower())
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug or "program"


def parse_scope_csv(
    csv_content: str,
    *,
    program: str = "",
    filename: str = "",
) -> dict[str, Any]:
    """Parse HackerOne-style scope CSV text into structured assets."""
    reader = csv.DictReader(io.StringIO(csv_content))
    if not reader.fieldnames:
        raise ValueError("CSV has no header row")

    program_name = program.strip()
    if not program_name and filename:
        match = re.search(r"scopes?_for_([a-zA-Z0-9]+?)(?:_at_|_\d)", filename.lower())
        if match:
            program_name = match.group(1).capitalize()
    if not program_name:
        program_name = "unspecified-program"

    id_col = next(
        (
            fn
            for fn in reader.fieldnames
            if fn.strip().lower() in ("identifier", "asset", "target", "scope", "url", "domain")
        ),
        None,
    )
    type_col = next(
        (fn for fn in reader.fieldnames if fn.strip().lower() in ("asset_type", "type", "category")),
        None,
    )
    bounty_col = next(
        (fn for fn in reader.fieldnames if fn.strip().lower() in ("eligible_for_bounty", "bounty", "eligible")),
        None,
    )
    severity_col = next(
        (fn for fn in reader.fieldnames if fn.strip().lower() in ("max_severity", "severity")),
        None,
    )
    instruction_col = next(
        (fn for fn in reader.fieldnames if fn.strip().lower() in ("instruction", "instructions", "description")),
        None,
    )

    assets: list[dict[str, Any]] = []
    for row in reader:
        identifier = (row.get(id_col) or "").strip() if id_col else ""
        if not identifier:
            continue
        eligible_raw = (row.get(bounty_col) or "true").strip().lower() if bounty_col else "true"
        assets.append(
            {
                "identifier": identifier,
                "type": (row.get(type_col) or "").strip() if type_col else "",
                "eligible": eligible_raw in ("true", "yes", "1", "in_scope"),
                "severity": (row.get(severity_col) or "").strip() if severity_col else "",
                "instruction": (row.get(instruction_col) or "").strip() if instruction_col else "",
            }
        )

    if not assets:
        raise ValueError("No scope assets found in CSV")

    in_scope = [a["identifier"] for a in assets if a["eligible"]]
    out_of_scope = [a["identifier"] for a in assets if not a["eligible"]]
    if not in_scope:
        in_scope = [a["identifier"] for a in assets]

    primary = None
    for asset in assets:
        if asset["eligible"] and asset["type"].lower() in ("url", "domain", "wildcard", "web", ""):
            primary = asset["identifier"]
            break
    if not primary:
        primary = assets[0]["identifier"]

    return {
        "program": program_name,
        "slug": _slugify(program_name),
        "primary_target": primary,
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "assets": assets,
        "total_assets": len(assets),
        "eligible_assets": len(in_scope),
    }


def write_program_bundle(
    *,
    programs_dir: str | Path,
    scopes_dir: str | Path,
    program: str,
    csv_content: str = "",
    guidelines: str = "",
    filename: str = "",
    forbidden_actions: list[str] | None = None,
    rate_limit_rps: float = 10.0,
) -> dict[str, Any]:
    """Persist scope CSV, guidelines, and Mythos scope YAML for a program."""
    programs_path = Path(programs_dir)
    scopes_path = Path(scopes_dir)
    programs_path.mkdir(parents=True, exist_ok=True)
    scopes_path.mkdir(parents=True, exist_ok=True)

    slug = _slugify(program)
    program_dir = programs_path / slug
    program_dir.mkdir(parents=True, exist_ok=True)

    parsed: dict[str, Any] | None = None
    if csv_content.strip():
        parsed = parse_scope_csv(csv_content, program=program, filename=filename)
        slug = parsed["slug"]
        program_dir = programs_path / slug
        program_dir.mkdir(parents=True, exist_ok=True)
        (program_dir / "scope.csv").write_text(csv_content, encoding="utf-8")

    if guidelines.strip():
        gpath = program_dir / "guidelines.md"
        if gpath.exists() and gpath.stat().st_size > 0:
            existing = gpath.read_text(encoding="utf-8")
            gpath.write_text(f"{existing.rstrip()}\n\n---\n\n{guidelines.strip()}\n", encoding="utf-8")
        else:
            gpath.write_text(guidelines.strip() + "\n", encoding="utf-8")

    scope_file = scopes_path / f"{slug}.yaml"
    if parsed:
        forbidden = forbidden_actions or ["dos", "destructive", "data_destruction"]
        lines = [
            f"program: {parsed['program']}",
            "allowed_hosts:",
            *[f'  - "{host}"' for host in parsed["in_scope"]],
        ]
        if parsed["out_of_scope"]:
            lines.append("out_of_scope_hosts:")
            lines.extend(f'  - "{host}"' for host in parsed["out_of_scope"])
        lines.extend(
            [
                "forbidden_actions:",
                *[f"  - {action}" for action in forbidden],
                f"rate_limit_rps: {rate_limit_rps}",
                "notes: >",
                "  Imported from Open WebUI.",
                f"  Primary target: {parsed['primary_target']}.",
                f"  {parsed['eligible_assets']}/{parsed['total_assets']} assets in scope.",
            ]
        )
        scope_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    meta = {
        "program": parsed["program"] if parsed else program,
        "slug": slug,
        "primary_target": parsed["primary_target"] if parsed else "",
        "scope_file": str(scope_file),
        "has_guidelines": bool(guidelines.strip()) or (program_dir / "guidelines.md").exists(),
        "has_scope": bool(parsed),
        "ready": bool(parsed) and (bool(guidelines.strip()) or (program_dir / "guidelines.md").exists()),
    }
    (program_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta