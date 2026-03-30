#!/usr/bin/env python3
"""Migrate RAG content from ~/dev/RAG/ into the BountyBud knowledge base."""

import os
import shutil
from pathlib import Path

# Mapping of source files to (target_path, frontmatter)
RAG_DIR = os.path.expanduser("~/dev/RAG")
KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "knowledge")

MIGRATIONS = [
    {
        "source": "methodology/dig-deep-asset-classes.md",
        "target": "methodologies/dig-deep-asset-classes.md",
        "frontmatter": {
            "id": "dig-deep-asset-classes",
            "title": "Dig Deep: Advanced Strategies for Different Asset Classes",
            "type": "methodology",
            "category": "reconnaissance",
            "subcategory": "osint",
            "tags": ["api-hunting", "javascript-analysis", "business-logic", "cloud", "graphql", "deep-dig", "ctf", "red-team"],
            "difficulty": "advanced",
            "platforms": ["linux", "macos", "windows"],
            "related": ["javascript-analysis", "graphql-grpc", "cloud-misconfigurations", "business-logic-flaws"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "methodology/business-logic-flaws-playbook.md",
        "target": "techniques/web/business-logic-flaws.md",
        "frontmatter": {
            "id": "business-logic-flaws",
            "title": "Business Logic Flaws Playbook (2026 Edition)",
            "type": "technique",
            "category": "web-application",
            "subcategory": "business-logic",
            "tags": ["business-logic", "price-manipulation", "workflow-bypass", "state-machine", "rounding-errors", "deep-dig"],
            "difficulty": "advanced",
            "platforms": ["linux", "macos", "windows"],
            "related": ["race-conditions", "idor-bola"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "web/javascript-analysis-masterclass.md",
        "target": "techniques/web/javascript-analysis.md",
        "frontmatter": {
            "id": "javascript-analysis",
            "title": "JavaScript Analysis Masterclass for Bug Bounty & Red Teaming",
            "type": "technique",
            "category": "web-application",
            "subcategory": "xss",
            "tags": ["javascript", "js-analysis", "secrets", "endpoints", "dom-xss", "prototype-pollution", "feature-flags", "deep-dig"],
            "difficulty": "intermediate",
            "platforms": ["linux", "macos", "windows"],
            "related": ["xss-techniques", "dig-deep-asset-classes", "ctf-web-playbook"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "web/idor-bola-hunting.md",
        "target": "techniques/web/idor-bola.md",
        "frontmatter": {
            "id": "idor-bola",
            "title": "IDOR & BOLA Hunting Masterclass (2026 Edition)",
            "type": "technique",
            "category": "web-application",
            "subcategory": "idor",
            "tags": ["idor", "bola", "uuid", "snowflake", "multi-tenant", "authorization", "api", "deep-dig"],
            "difficulty": "intermediate",
            "platforms": ["linux", "macos", "windows"],
            "related": ["graphql-grpc", "business-logic-flaws"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "web/ssrf-modern-techniques-and-bypasses.md",
        "target": "techniques/web/ssrf.md",
        "frontmatter": {
            "id": "ssrf-techniques",
            "title": "SSRF Modern Techniques & Bypasses (2026 Edition)",
            "type": "technique",
            "category": "web-application",
            "subcategory": "ssrf",
            "tags": ["ssrf", "dns-rebinding", "imdsv2", "cloud-metadata", "gopher", "parser-differential", "deep-dig"],
            "difficulty": "advanced",
            "platforms": ["linux", "macos", "windows"],
            "related": ["cloud-misconfigurations", "oauth-jwt-saml-bypasses"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "web/race-conditions-toctou.md",
        "target": "techniques/web/race-conditions.md",
        "frontmatter": {
            "id": "race-conditions",
            "title": "Race Conditions & TOCTOU Masterclass (2026)",
            "type": "technique",
            "category": "web-application",
            "subcategory": "race-conditions",
            "tags": ["race-condition", "toctou", "turbo-intruder", "parallel-requests", "state-desync", "deep-dig"],
            "difficulty": "advanced",
            "platforms": ["linux", "macos", "windows"],
            "related": ["business-logic-flaws"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "web/ctf-web-playbook.md",
        "target": "methodologies/ctf-web-playbook.md",
        "frontmatter": {
            "id": "ctf-web-playbook",
            "title": "CTF Web Playbook - Flag Hunting Edition",
            "type": "methodology",
            "category": "web-application",
            "subcategory": "xss",
            "tags": ["ctf", "web", "git-exposure", "prototype-pollution", "graphql", "source-maps", "deep-dig"],
            "difficulty": "intermediate",
            "platforms": ["linux", "macos", "windows"],
            "related": ["javascript-analysis", "dig-deep-asset-classes"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "api/graphql-grpc-hunting.md",
        "target": "techniques/api/graphql-grpc.md",
        "frontmatter": {
            "id": "graphql-grpc",
            "title": "GraphQL & gRPC Hunting Masterclass (2026 Edition)",
            "type": "technique",
            "category": "api-security",
            "subcategory": "graphql",
            "tags": ["graphql", "grpc", "protobuf", "introspection", "batching", "alias-dos", "deep-dig"],
            "difficulty": "advanced",
            "platforms": ["linux", "macos", "windows"],
            "related": ["idor-bola", "dig-deep-asset-classes"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "cloud/cloud-misconfigurations-aws-gcp-azure.md",
        "target": "techniques/cloud/cloud-misconfigurations.md",
        "frontmatter": {
            "id": "cloud-misconfigurations",
            "title": "Cloud Misconfigurations Playbook - AWS / GCP / Azure (2026)",
            "type": "technique",
            "category": "cloud",
            "subcategory": "aws",
            "tags": ["cloud", "aws", "gcp", "azure", "s3", "iam", "metadata", "bucket", "misconfiguration", "deep-dig"],
            "difficulty": "intermediate",
            "platforms": ["linux", "macos", "windows"],
            "related": ["ssrf-techniques", "dig-deep-asset-classes"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "mobile/mobile-frida-apk-testing.md",
        "target": "techniques/mobile/frida-apk-testing.md",
        "frontmatter": {
            "id": "frida-apk-testing",
            "title": "Mobile Hunting: Frida + APK Masterclass (Android/iOS 2026)",
            "type": "technique",
            "category": "mobile",
            "subcategory": "android",
            "tags": ["mobile", "frida", "objection", "android", "ios", "apk", "ssl-pinning", "runtime-hooking", "deep-dig"],
            "difficulty": "advanced",
            "platforms": ["linux", "macos", "windows"],
            "related": [],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "auth/oauth-jwt-saml-bypasses.md",
        "target": "techniques/web/oauth-jwt-saml-bypasses.md",
        "frontmatter": {
            "id": "oauth-jwt-saml-bypasses",
            "title": "OAuth / JWT / SAML Auth Bypass Masterclass (2026)",
            "type": "technique",
            "category": "web-application",
            "subcategory": "authentication",
            "tags": ["oauth", "jwt", "saml", "auth-bypass", "algorithm-confusion", "token", "xxe", "deep-dig"],
            "difficulty": "advanced",
            "platforms": ["linux", "macos", "windows"],
            "related": ["ssrf-techniques", "idor-bola"],
            "updated": "2026-03-30",
        },
    },
    {
        "source": "reporting/reporting-payout-maximization.md",
        "target": "reporting/payout-maximization.md",
        "frontmatter": {
            "id": "payout-maximization",
            "title": "Reporting & Payout Maximization Templates",
            "type": "report-template",
            "category": "reporting",
            "subcategory": "payout-maximization",
            "tags": ["reporting", "payout", "templates", "poc", "severity", "deep-dig"],
            "difficulty": "beginner",
            "platforms": ["linux", "macos", "windows"],
            "related": [],
            "updated": "2026-03-30",
        },
    },
]


def build_frontmatter(fm: dict) -> str:
    """Build YAML frontmatter string from dict."""
    lines = ["---"]
    for key in ["id", "title", "type", "category", "subcategory"]:
        lines.append(f'{key}: "{fm[key]}"')

    # List fields
    for key in ["tags", "platforms", "related"]:
        if fm.get(key):
            items = ", ".join(f'"{v}"' for v in fm[key])
            lines.append(f"{key}: [{items}]")
        else:
            lines.append(f"{key}: []")

    lines.append(f'difficulty: "{fm["difficulty"]}"')
    lines.append(f'updated: "{fm["updated"]}"')
    lines.append("---")
    return "\n".join(lines)


def migrate_file(migration: dict):
    """Copy a RAG file into the knowledge base with frontmatter prepended."""
    source_path = os.path.join(RAG_DIR, migration["source"])
    target_path = os.path.join(KNOWLEDGE_DIR, migration["target"])

    if not os.path.exists(source_path):
        print(f"  SKIP (not found): {source_path}")
        return False

    # Read source content
    with open(source_path, "r") as f:
        content = f.read()

    # Build frontmatter
    fm_str = build_frontmatter(migration["frontmatter"])

    # Ensure target directory exists
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    # Write target with frontmatter + original content
    with open(target_path, "w") as f:
        f.write(fm_str + "\n\n" + content)

    print(f"  OK: {migration['source']} -> {migration['target']}")
    return True


def main():
    print(f"Migrating RAG content from {RAG_DIR} to {KNOWLEDGE_DIR}")
    print(f"Files to migrate: {len(MIGRATIONS)}")
    print()

    success = 0
    for migration in MIGRATIONS:
        if migrate_file(migration):
            success += 1

    print(f"\nDone: {success}/{len(MIGRATIONS)} files migrated successfully.")


if __name__ == "__main__":
    main()
