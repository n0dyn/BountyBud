#!/usr/bin/env python3
"""Convert command_templates.json tools into markdown knowledge files."""

import json
import os
import re

COMMANDS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "data", "command_templates.json")
KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "knowledge", "tools")

# Map JSON category keys to taxonomy values
CATEGORY_MAP = {
    "subdomain": ("reconnaissance", "subdomain-enumeration"),
    "url": ("reconnaissance", "url-collection"),
    "directory": ("reconnaissance", "directory-discovery"),
    "sensitive": ("reconnaissance", "sensitive-data-discovery"),
    "parameter": ("reconnaissance", "parameter-discovery"),
    "javascript": ("reconnaissance", "javascript-analysis"),
    "lfi": ("web-application", "lfi"),
    "cors": ("web-application", "cors"),
    "vuln": ("web-application", "xss"),
    "webapp": ("web-application", "xss"),
    "wordpress": ("cms", "wordpress"),
    "network": ("network", "port-scanning"),
    "service": ("network", "service-enumeration"),
    "osint": ("reconnaissance", "osint"),
    "api": ("api-security", "rest"),
    "mobile": ("mobile", "android"),
    "cloud": ("cloud", "aws"),
}


def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_]+', '-', text)
    text = re.sub(r'-+', '-', text)
    return text.strip('-')


def build_tool_markdown(tool: dict, category_key: str, category_name: str) -> str:
    """Build a markdown file for a single tool."""
    tool_id = tool["id"]
    name = tool.get("name", tool_id)
    description = tool.get("description", "")
    command = tool.get("command", "")
    docs_url = tool.get("docs_url", "")
    features = tool.get("features", [])
    tool_category = tool.get("category", "")

    cat, subcat = CATEGORY_MAP.get(category_key, ("reconnaissance", "subdomain-enumeration"))

    tags = [slugify(category_key), tool_id]
    if tool_category:
        tags.append(slugify(tool_category))
    if features:
        for f in features[:3]:
            tags.append(slugify(f))

    # Remove duplicates while preserving order
    seen = set()
    unique_tags = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            unique_tags.append(t)

    tags_str = ", ".join(f'"{t}"' for t in unique_tags)

    lines = [
        "---",
        f'id: "{tool_id}"',
        f'title: "{name}"',
        'type: "tool"',
        f'category: "{cat}"',
        f'subcategory: "{subcat}"',
        f'tags: [{tags_str}]',
        'difficulty: "beginner"',
        'platforms: ["linux", "macos"]',
    ]

    if docs_url:
        lines.append(f'source_url: "{docs_url}"')

    lines.append('related: []')
    lines.append('updated: "2026-03-30"')
    lines.append("---")
    lines.append("")
    lines.append(f"## Overview")
    lines.append("")
    lines.append(description)
    lines.append("")

    if command:
        lines.append("## Command Reference")
        lines.append("")
        lines.append("```bash")
        lines.append(command)
        lines.append("```")
        lines.append("")

    if features:
        lines.append("## Features")
        lines.append("")
        for f in features:
            lines.append(f"- {f}")
        lines.append("")

    if docs_url:
        lines.append("## Documentation")
        lines.append("")
        lines.append(f"- [Official Documentation]({docs_url})")
        lines.append("")

    return "\n".join(lines)


def main():
    with open(COMMANDS_FILE, "r") as f:
        templates = json.load(f)

    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)

    count = 0
    for category_key, category_data in templates.items():
        category_name = category_data.get("name", category_key)
        tools = category_data.get("tools", [])

        for tool in tools:
            tool_id = tool["id"]
            content = build_tool_markdown(tool, category_key, category_name)

            filepath = os.path.join(KNOWLEDGE_DIR, f"{tool_id}.md")
            with open(filepath, "w") as f:
                f.write(content)

            print(f"  OK: {tool_id} ({category_name})")
            count += 1

    print(f"\nDone: {count} tool files created.")


if __name__ == "__main__":
    main()
