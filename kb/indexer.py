"""Build and manage the SQLite FTS5 search index."""

import json
import os
import sqlite3
from pathlib import Path

import markdown

from kb.loader import load_all_documents


DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'kb_index.db')
KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'knowledge')


def get_db_connection() -> sqlite3.Connection:
    """Get a connection to the index database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection):
    """Create database tables."""
    conn.executescript('''
        DROP TABLE IF EXISTS kb_chunks;
        DROP TABLE IF EXISTS documents;

        CREATE VIRTUAL TABLE kb_chunks USING fts5(
            chunk_id,
            document_id,
            title,
            section,
            content,
            type,
            category,
            subcategory,
            tags,
            difficulty,
            token_count UNINDEXED
        );

        CREATE TABLE documents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            type TEXT,
            category TEXT,
            subcategory TEXT,
            tags TEXT,
            difficulty TEXT,
            platforms TEXT,
            related TEXT,
            updated TEXT,
            metadata_json TEXT,
            body_markdown TEXT,
            body_html TEXT
        );
    ''')


def build_index(knowledge_dir: str = None):
    """Rebuild the entire search index from knowledge files."""
    if knowledge_dir is None:
        knowledge_dir = KNOWLEDGE_DIR

    conn = get_db_connection()
    try:
        init_db(conn)

        md = markdown.Markdown(extensions=['fenced_code', 'tables', 'codehilite'])
        documents = load_all_documents(knowledge_dir)

        for metadata, body, chunks in documents:
            doc_id = metadata.get('id', '')
            tags_str = ','.join(metadata.get('tags', []))
            platforms_str = ','.join(metadata.get('platforms', []))
            related_str = ','.join(metadata.get('related', []))

            md.reset()
            body_html = md.convert(body)

            # Insert into documents table
            conn.execute('''
                INSERT OR REPLACE INTO documents
                (id, title, type, category, subcategory, tags, difficulty,
                 platforms, related, updated, metadata_json, body_markdown, body_html)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                doc_id,
                metadata.get('title', ''),
                metadata.get('type', ''),
                metadata.get('category', ''),
                metadata.get('subcategory', ''),
                tags_str,
                metadata.get('difficulty', ''),
                platforms_str,
                related_str,
                metadata.get('updated', ''),
                json.dumps(metadata),
                body,
                body_html,
            ))

            # Insert chunks into FTS table
            for chunk in chunks:
                conn.execute('''
                    INSERT INTO kb_chunks
                    (chunk_id, document_id, title, section, content,
                     type, category, subcategory, tags, difficulty, token_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    chunk.chunk_id,
                    chunk.document_id,
                    chunk.title,
                    chunk.section,
                    chunk.content,
                    metadata.get('type', ''),
                    metadata.get('category', ''),
                    metadata.get('subcategory', ''),
                    tags_str,
                    metadata.get('difficulty', ''),
                    chunk.token_count,
                ))

        conn.commit()
        doc_count = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
        chunk_count = conn.execute('SELECT COUNT(*) FROM kb_chunks').fetchone()[0]
        return {'documents': doc_count, 'chunks': chunk_count}

    finally:
        conn.close()


def is_index_stale(knowledge_dir: str = None) -> bool:
    """Check if the index needs rebuilding (knowledge files newer than index)."""
    if knowledge_dir is None:
        knowledge_dir = KNOWLEDGE_DIR

    if not os.path.exists(DB_PATH):
        return True

    db_mtime = os.path.getmtime(DB_PATH)
    knowledge_path = Path(knowledge_dir)

    for md_file in knowledge_path.rglob('*.md'):
        if md_file.name.startswith('_'):
            continue
        if os.path.getmtime(md_file) > db_mtime:
            return True

    return False


def ensure_index(knowledge_dir: str = None):
    """Build index if it doesn't exist or is stale."""
    if is_index_stale(knowledge_dir):
        return build_index(knowledge_dir)
    return None
