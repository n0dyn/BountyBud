"""Query logic for the knowledge base search."""

import json
import sqlite3

from kb.indexer import get_db_connection


def search_chunks(
    query: str = None,
    doc_type: str = None,
    category: str = None,
    subcategory: str = None,
    tags: list[str] = None,
    difficulty: str = None,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    """Search knowledge base chunks with full-text search and metadata filtering.

    Returns dict with results, total count, and query metadata.
    """
    conn = get_db_connection()
    try:
        conditions = []
        params = []

        if query:
            # Use FTS5 MATCH for full-text search
            conditions.append('kb_chunks MATCH ?')
            # Split into words and join with AND for multi-word queries
            # Search across content, title, and section columns
            words = query.strip().split()
            safe_words = [w.replace('"', '""') for w in words if w]
            if len(safe_words) == 1:
                fts_query = f'"{safe_words[0]}"'
            elif len(safe_words) <= 3:
                # Short queries: use AND for precision
                fts_query = ' AND '.join(f'"{w}"' for w in safe_words)
            else:
                # Longer queries: use OR to avoid zero results, BM25 handles ranking
                fts_query = ' OR '.join(f'"{w}"' for w in safe_words)
            params.append(fts_query)

        if doc_type:
            conditions.append('type = ?')
            params.append(doc_type)

        if category:
            conditions.append('category = ?')
            params.append(category)

        if subcategory:
            conditions.append('subcategory = ?')
            params.append(subcategory)

        if difficulty:
            conditions.append('difficulty = ?')
            params.append(difficulty)

        if tags:
            for tag in tags:
                conditions.append('tags LIKE ?')
                params.append(f'%{tag}%')

        where_clause = ' AND '.join(conditions) if conditions else '1=1'

        # Get total count
        count_sql = f'SELECT COUNT(*) FROM kb_chunks WHERE {where_clause}'
        total = conn.execute(count_sql, params).fetchone()[0]

        # Get results with relevance ranking
        if query:
            select_sql = f'''
                SELECT chunk_id, document_id, title, section, content,
                       type, category, subcategory, tags, difficulty, token_count,
                       bm25(kb_chunks) as relevance_score
                FROM kb_chunks
                WHERE {where_clause}
                ORDER BY relevance_score
                LIMIT ? OFFSET ?
            '''
        else:
            select_sql = f'''
                SELECT chunk_id, document_id, title, section, content,
                       type, category, subcategory, tags, difficulty, token_count,
                       0 as relevance_score
                FROM kb_chunks
                WHERE {where_clause}
                ORDER BY document_id, chunk_id
                LIMIT ? OFFSET ?
            '''

        params.extend([limit, offset])
        rows = conn.execute(select_sql, params).fetchall()

        results = []
        for row in rows:
            results.append({
                'chunk_id': row['chunk_id'],
                'document_id': row['document_id'],
                'title': row['title'],
                'section': row['section'],
                'content': row['content'],
                'metadata': {
                    'type': row['type'],
                    'category': row['category'],
                    'subcategory': row['subcategory'],
                    'tags': [t for t in row['tags'].split(',') if t],
                    'difficulty': row['difficulty'],
                },
                'relevance_score': abs(row['relevance_score']),
                'token_count': row['token_count'],
            })

        return {
            'query': query,
            'total': total,
            'limit': limit,
            'offset': offset,
            'results': results,
        }

    finally:
        conn.close()


def get_document(doc_id: str) -> dict | None:
    """Retrieve a full document by ID."""
    conn = get_db_connection()
    try:
        row = conn.execute(
            'SELECT * FROM documents WHERE id = ?', (doc_id,)
        ).fetchone()

        if not row:
            return None

        return {
            'id': row['id'],
            'title': row['title'],
            'metadata': json.loads(row['metadata_json']),
            'body_markdown': row['body_markdown'],
            'body_html': row['body_html'],
        }
    finally:
        conn.close()


def get_manifest() -> list[dict]:
    """Return metadata for all documents (no body content)."""
    conn = get_db_connection()
    try:
        rows = conn.execute('''
            SELECT id, title, type, category, subcategory, tags,
                   difficulty, platforms, related, updated
            FROM documents
            ORDER BY category, subcategory, title
        ''').fetchall()

        return [
            {
                'id': row['id'],
                'title': row['title'],
                'type': row['type'],
                'category': row['category'],
                'subcategory': row['subcategory'],
                'tags': [t for t in row['tags'].split(',') if t],
                'difficulty': row['difficulty'],
                'platforms': [p for p in row['platforms'].split(',') if p],
                'related': [r for r in row['related'].split(',') if r],
                'updated': row['updated'],
            }
            for row in rows
        ]
    finally:
        conn.close()


def get_stats() -> dict:
    """Return aggregate statistics about the knowledge base."""
    conn = get_db_connection()
    try:
        stats = {
            'total_documents': conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0],
            'total_chunks': conn.execute('SELECT COUNT(*) FROM kb_chunks').fetchone()[0],
            'by_type': {},
            'by_category': {},
            'by_difficulty': {},
        }

        for row in conn.execute('SELECT type, COUNT(*) as cnt FROM documents GROUP BY type'):
            stats['by_type'][row['type']] = row['cnt']

        for row in conn.execute('SELECT category, COUNT(*) as cnt FROM documents GROUP BY category'):
            stats['by_category'][row['category']] = row['cnt']

        for row in conn.execute('SELECT difficulty, COUNT(*) as cnt FROM documents GROUP BY difficulty'):
            stats['by_difficulty'][row['difficulty']] = row['cnt']

        return stats
    finally:
        conn.close()


def get_related(doc_id: str) -> list[dict]:
    """Get documents related to a given document."""
    conn = get_db_connection()
    try:
        # Get the document's related field and tags
        doc = conn.execute(
            'SELECT related, tags, category FROM documents WHERE id = ?', (doc_id,)
        ).fetchone()

        if not doc:
            return []

        related_ids = [r for r in doc['related'].split(',') if r]
        doc_tags = set(doc['tags'].split(','))
        results = []

        # Get explicitly related documents
        if related_ids:
            placeholders = ','.join('?' * len(related_ids))
            rows = conn.execute(f'''
                SELECT id, title, type, category, subcategory, tags, difficulty
                FROM documents WHERE id IN ({placeholders})
            ''', related_ids).fetchall()

            for row in rows:
                results.append({
                    'id': row['id'],
                    'title': row['title'],
                    'type': row['type'],
                    'category': row['category'],
                    'subcategory': row['subcategory'],
                    'tags': [t for t in row['tags'].split(',') if t],
                    'difficulty': row['difficulty'],
                    'relation': 'explicit',
                })

        # Find tag-similar documents in same category
        rows = conn.execute('''
            SELECT id, title, type, category, subcategory, tags, difficulty
            FROM documents
            WHERE category = ? AND id != ?
            LIMIT 10
        ''', (doc['category'], doc_id)).fetchall()

        seen_ids = {r['id'] for r in results}
        for row in rows:
            if row['id'] in seen_ids:
                continue
            row_tags = set(row['tags'].split(','))
            overlap = len(doc_tags & row_tags)
            if overlap > 0:
                results.append({
                    'id': row['id'],
                    'title': row['title'],
                    'type': row['type'],
                    'category': row['category'],
                    'subcategory': row['subcategory'],
                    'tags': [t for t in row['tags'].split(',') if t],
                    'difficulty': row['difficulty'],
                    'relation': 'tag_similarity',
                    'shared_tags': overlap,
                })

        return results
    finally:
        conn.close()


def get_taxonomy() -> dict:
    """Return the taxonomy with actual document counts per category."""
    conn = get_db_connection()
    try:
        taxonomy = {}

        rows = conn.execute('''
            SELECT category, subcategory, COUNT(*) as cnt
            FROM documents
            GROUP BY category, subcategory
            ORDER BY category, subcategory
        ''').fetchall()

        for row in rows:
            cat = row['category']
            if cat not in taxonomy:
                taxonomy[cat] = {'subcategories': {}, 'total': 0}
            sub = row['subcategory']
            if sub:
                taxonomy[cat]['subcategories'][sub] = row['cnt']
            taxonomy[cat]['total'] += row['cnt']

        # Also include type counts
        type_counts = {}
        for row in conn.execute('SELECT type, COUNT(*) as cnt FROM documents GROUP BY type'):
            type_counts[row['type']] = row['cnt']

        return {'categories': taxonomy, 'types': type_counts}
    finally:
        conn.close()
