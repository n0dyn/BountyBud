#!/usr/bin/env python3
"""Convert xss_payloads.json into markdown knowledge files."""

import json
import os

PAYLOADS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "data", "xss_payloads.json")
KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "knowledge", "payloads", "xss")


def main():
    with open(PAYLOADS_FILE, "r") as f:
        data = json.load(f)

    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)

    categories = data.get("categories", {})
    contexts = data.get("contexts", {})
    count = 0

    for cat_key, cat_data in categories.items():
        cat_name = cat_data.get("name", cat_key)
        cat_desc = cat_data.get("description", "")
        payloads = cat_data.get("payloads", [])

        tags = ["xss", cat_key, "payload"]
        tags_str = ", ".join(f'"{t}"' for t in tags)

        difficulty = "beginner" if cat_key == "basic" else "intermediate"
        if cat_key in ("bypass", "advanced", "blind"):
            difficulty = "advanced"

        lines = [
            "---",
            f'id: "xss-{cat_key}-payloads"',
            f'title: "XSS Payloads - {cat_name}"',
            'type: "payload"',
            'category: "web-application"',
            'subcategory: "xss"',
            f'tags: [{tags_str}]',
            f'difficulty: "{difficulty}"',
            'platforms: ["linux", "macos", "windows"]',
            'related: ["xss-techniques"]',
            'updated: "2026-03-30"',
            "---",
            "",
            f"## Overview",
            "",
            cat_desc if cat_desc else f"{cat_name} XSS payloads for security testing.",
            "",
            "## Payloads",
            "",
        ]

        for payload in payloads:
            p_name = payload.get("name", "Unnamed")
            p_desc = payload.get("description", "")
            p_payload = payload.get("payload", "")
            p_contexts = payload.get("contexts", [])
            p_severity = payload.get("severity", "")

            lines.append(f"### {p_name}")
            lines.append("")
            if p_desc:
                lines.append(p_desc)
                lines.append("")
            if p_contexts:
                lines.append(f"- **Contexts**: {', '.join(p_contexts)}")
            if p_severity:
                lines.append(f"- **Severity**: {p_severity}")
            lines.append("")
            lines.append("```html")
            lines.append(p_payload)
            lines.append("```")
            lines.append("")

        filepath = os.path.join(KNOWLEDGE_DIR, f"{cat_key}.md")
        with open(filepath, "w") as f:
            f.write("\n".join(lines))

        print(f"  OK: xss/{cat_key}.md ({len(payloads)} payloads)")
        count += 1

    # Also create a context reference doc
    if contexts:
        lines = [
            "---",
            'id: "xss-context-reference"',
            'title: "XSS Injection Contexts Reference"',
            'type: "cheatsheet"',
            'category: "web-application"',
            'subcategory: "xss"',
            'tags: ["xss", "context", "cheatsheet"]',
            'difficulty: "intermediate"',
            'platforms: ["linux", "macos", "windows"]',
            'related: ["xss-techniques"]',
            'updated: "2026-03-30"',
            "---",
            "",
            "## XSS Injection Contexts",
            "",
            "Understanding the injection context is critical for crafting effective XSS payloads.",
            "",
        ]

        for ctx_key, ctx_data in contexts.items():
            ctx_name = ctx_data.get("name", ctx_key)
            ctx_desc = ctx_data.get("description", "")
            lines.append(f"### {ctx_name}")
            lines.append("")
            if ctx_desc:
                lines.append(ctx_desc)
                lines.append("")

        filepath = os.path.join(KNOWLEDGE_DIR, "context-reference.md")
        with open(filepath, "w") as f:
            f.write("\n".join(lines))
        print(f"  OK: xss/context-reference.md")
        count += 1

    print(f"\nDone: {count} payload files created.")


if __name__ == "__main__":
    main()
