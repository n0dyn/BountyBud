"""RAG API endpoints for the knowledge base."""

import os

from flask import jsonify, request

from kb import kb_bp
from kb.indexer import build_index, ensure_index
from kb.search import (
    get_document,
    get_manifest,
    get_related,
    get_stats,
    get_taxonomy,
    search_chunks,
)

def add_cors_headers(response):
    """Add CORS headers for cross-origin AI agent access."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


@kb_bp.after_request
def after_request(response):
    return add_cors_headers(response)


@kb_bp.before_request
def before_request():
    """Ensure index exists before handling requests."""
    ensure_index()


@kb_bp.route('/search')
def kb_search():
    """Full-text search with metadata filtering.

    Query params: q, type, category, subcategory, tags (comma-separated),
                  difficulty, limit, offset
    """
    q = request.args.get('q')
    doc_type = request.args.get('type')
    category = request.args.get('category')
    subcategory = request.args.get('subcategory')
    tags_str = request.args.get('tags')
    difficulty = request.args.get('difficulty')
    limit = request.args.get('limit', 20, type=int)
    offset = request.args.get('offset', 0, type=int)

    tags = [t.strip() for t in tags_str.split(',') if t.strip()] if tags_str else None

    result = search_chunks(
        query=q,
        doc_type=doc_type,
        category=category,
        subcategory=subcategory,
        tags=tags,
        difficulty=difficulty,
        limit=min(limit, 100),
        offset=offset,
    )

    return jsonify({'success': True, 'data': result})


@kb_bp.route('/chunks')
def kb_chunks():
    """Return pre-chunked content ready for embedding.

    Same filters as /search. Returns array of chunks with metadata and token counts.
    """
    q = request.args.get('q')
    doc_type = request.args.get('type')
    category = request.args.get('category')
    subcategory = request.args.get('subcategory')
    tags_str = request.args.get('tags')
    difficulty = request.args.get('difficulty')
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)

    tags = [t.strip() for t in tags_str.split(',') if t.strip()] if tags_str else None

    result = search_chunks(
        query=q,
        doc_type=doc_type,
        category=category,
        subcategory=subcategory,
        tags=tags,
        difficulty=difficulty,
        limit=min(limit, 200),
        offset=offset,
    )

    # Reshape for embedding consumption
    chunks = [{
        'chunk_id': r['chunk_id'],
        'document_id': r['document_id'],
        'text': r['content'],
        'metadata': r['metadata'],
        'token_count': r['token_count'],
    } for r in result['results']]

    return jsonify({
        'success': True,
        'data': {
            'chunks': chunks,
            'total': result['total'],
            'limit': result['limit'],
            'offset': result['offset'],
        }
    })


@kb_bp.route('/document/<doc_id>')
def kb_document(doc_id):
    """Retrieve a single full document by ID."""
    doc = get_document(doc_id)
    if not doc:
        return jsonify({'success': False, 'error': 'Document not found'}), 404

    return jsonify({'success': True, 'data': doc})


@kb_bp.route('/taxonomy')
def kb_taxonomy():
    """Return the full taxonomy tree with document counts."""
    return jsonify({'success': True, 'data': get_taxonomy()})


@kb_bp.route('/stats')
def kb_stats():
    """Return aggregate statistics about the knowledge base."""
    return jsonify({'success': True, 'data': get_stats()})


@kb_bp.route('/related/<doc_id>')
def kb_related(doc_id):
    """Return documents related to a given document ID."""
    related = get_related(doc_id)
    return jsonify({'success': True, 'data': related})


@kb_bp.route('/manifest')
def kb_manifest():
    """Return a complete manifest of all documents (metadata only, no body)."""
    manifest = get_manifest()
    return jsonify({
        'success': True,
        'data': {
            'documents': manifest,
            'total': len(manifest),
        }
    })


@kb_bp.route('/reindex', methods=['POST'])
def kb_reindex():
    """Trigger a rebuild of the search index."""
    result = build_index()
    return jsonify({
        'success': True,
        'data': result,
        'message': 'Index rebuilt successfully',
    })
