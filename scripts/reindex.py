#!/usr/bin/env python3
"""Rebuild the knowledge base search index."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from kb.indexer import build_index

if __name__ == "__main__":
    print("Rebuilding knowledge base index...")
    result = build_index()
    print(f"Done: {result['documents']} documents, {result['chunks']} chunks indexed.")
