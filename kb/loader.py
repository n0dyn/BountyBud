"""Parse markdown files with YAML frontmatter into chunks for RAG."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import frontmatter


@dataclass
class Chunk:
    chunk_id: str
    document_id: str
    title: str
    section: str
    content: str
    content_markdown: str
    metadata: dict = field(default_factory=dict)
    token_count: int = 0


def slugify(text: str) -> str:
    """Convert text to a URL-friendly slug."""
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_]+', '-', text)
    text = re.sub(r'-+', '-', text)
    return text.strip('-')


def estimate_tokens(text: str) -> int:
    """Estimate token count (words * 1.3 approximation)."""
    words = len(text.split())
    return int(words * 1.3)


def parse_document(filepath: str) -> tuple[dict, str]:
    """Parse a markdown file with YAML frontmatter.

    Returns (metadata_dict, body_markdown).
    """
    post = frontmatter.load(filepath)
    metadata = dict(post.metadata)
    return metadata, post.content


def split_into_chunks(
    document_id: str,
    title: str,
    body: str,
    metadata: dict,
    max_tokens: int = 800,
) -> list[Chunk]:
    """Split markdown body into chunks on H2 boundaries.

    If a section exceeds max_tokens, further split on H3 or paragraph breaks.
    """
    # Split on H2 headings, keeping the heading text
    h2_pattern = re.compile(r'^## (.+)$', re.MULTILINE)
    sections = []
    last_end = 0
    last_heading = "overview"

    for match in h2_pattern.finditer(body):
        if last_end > 0 or body[:match.start()].strip():
            content = body[last_end:match.start()].strip()
            if content:
                sections.append((last_heading, content))
        last_heading = match.group(1).strip()
        last_end = match.end()

    # Remaining content after last H2
    remaining = body[last_end:].strip()
    if remaining:
        sections.append((last_heading, remaining))

    # If no H2 headings found, treat entire body as one section
    if not sections and body.strip():
        sections.append(("overview", body.strip()))

    chunks = []
    for section_heading, section_content in sections:
        section_slug = slugify(section_heading)
        tokens = estimate_tokens(section_content)

        if tokens <= max_tokens:
            chunk_id = f"{document_id}__{section_slug}"
            chunks.append(Chunk(
                chunk_id=chunk_id,
                document_id=document_id,
                title=title,
                section=section_heading,
                content=section_content,
                content_markdown=section_content,
                metadata=metadata.copy(),
                token_count=tokens,
            ))
        else:
            # Further split on H3 or paragraph breaks
            sub_chunks = _split_large_section(
                document_id, title, section_heading, section_slug,
                section_content, metadata, max_tokens
            )
            chunks.extend(sub_chunks)

    return chunks


def _split_large_section(
    document_id: str,
    title: str,
    section_heading: str,
    section_slug: str,
    content: str,
    metadata: dict,
    max_tokens: int,
) -> list[Chunk]:
    """Split an oversized section on H3 headings or paragraph breaks."""
    # Try H3 split first
    h3_pattern = re.compile(r'^### (.+)$', re.MULTILINE)
    h3_matches = list(h3_pattern.finditer(content))

    if h3_matches:
        parts = []
        last_end = 0
        last_sub_heading = section_heading

        for match in h3_matches:
            text = content[last_end:match.start()].strip()
            if text:
                parts.append((last_sub_heading, text))
            last_sub_heading = f"{section_heading} > {match.group(1).strip()}"
            last_end = match.end()

        remaining = content[last_end:].strip()
        if remaining:
            parts.append((last_sub_heading, remaining))
    else:
        # Fall back to paragraph splitting
        paragraphs = re.split(r'\n\n+', content)
        parts = []
        current_text = ""
        part_idx = 0

        for para in paragraphs:
            if estimate_tokens(current_text + "\n\n" + para) > max_tokens and current_text:
                parts.append((f"{section_heading} (part {part_idx + 1})", current_text.strip()))
                current_text = para
                part_idx += 1
            else:
                current_text = (current_text + "\n\n" + para).strip()

        if current_text:
            parts.append((f"{section_heading} (part {part_idx + 1})", current_text.strip()))

    chunks = []
    for i, (sub_heading, text) in enumerate(parts):
        sub_slug = slugify(sub_heading)
        chunk_id = f"{document_id}__{sub_slug}"
        # Ensure unique chunk IDs
        if any(c.chunk_id == chunk_id for c in chunks):
            chunk_id = f"{chunk_id}-{i}"

        chunks.append(Chunk(
            chunk_id=chunk_id,
            document_id=document_id,
            title=title,
            section=sub_heading,
            content=text,
            content_markdown=text,
            metadata=metadata.copy(),
            token_count=estimate_tokens(text),
        ))

    return chunks


def load_all_documents(knowledge_dir: str) -> list[tuple[dict, str, list[Chunk]]]:
    """Load all markdown files from the knowledge directory.

    Returns list of (metadata, full_body, chunks) tuples.
    """
    knowledge_path = Path(knowledge_dir)
    documents = []

    for md_file in sorted(knowledge_path.rglob('*.md')):
        # Skip files starting with _ (like _schema.yaml)
        if md_file.name.startswith('_'):
            continue

        try:
            metadata, body = parse_document(str(md_file))

            # Ensure required fields
            if 'id' not in metadata:
                metadata['id'] = md_file.stem

            if 'title' not in metadata:
                metadata['title'] = md_file.stem.replace('-', ' ').title()

            doc_id = metadata['id']
            title = metadata['title']

            chunks = split_into_chunks(doc_id, title, body, metadata)
            documents.append((metadata, body, chunks))

        except Exception as e:
            print(f"Warning: Failed to parse {md_file}: {e}")
            continue

    return documents
