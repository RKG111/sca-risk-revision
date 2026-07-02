"""
Module 1 — Codebase Indexer

Orchestrates Tree-sitter parsing + vector DB indexing.
Produces a token-optimized structural map that agents can query
without needing to load raw source files into the LLM context.
"""

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CodeIndex:
    """
    Lightweight in-memory index produced by the Indexer.
    Agents query this object rather than the raw filesystem.
    """

    def __init__(self, skeletons: list, collection_name: str = "code_index"):
        self.skeletons = skeletons
        self.collection_name = collection_name
        self._import_map: dict[str, list[str]] = {}
        self._function_map: dict[str, list[dict]] = {}
        self._build_maps()

    def _build_maps(self):
        for skeleton in self.skeletons:
            for imp in skeleton.imports:
                self._import_map.setdefault(imp.module, []).append(skeleton.file_path)
            for func in skeleton.functions:
                self._function_map.setdefault(func.name, []).append({
                    "file": func.file_path,
                    "line": func.line,
                    "params": func.parameters,
                })

    def files_importing(self, module: str) -> list[str]:
        """Returns all files that import the given module (or its prefix)."""
        return [
            path
            for mod, paths in self._import_map.items()
            if mod == module or mod.startswith(module + ".")
            for path in paths
        ]

    def find_function(self, name: str) -> list[dict]:
        """Returns all locations where a function/method with the given name is defined."""
        return self._function_map.get(name, [])

    def contains_indicator(self, indicator: str) -> list[str]:
        """
        Scans raw source for a string indicator (e.g. 'yaml.load(').
        Returns list of file paths containing the indicator.
        Note: This is a simple substring scan — use Semgrep for semantic matching.
        """
        matches = []
        for skeleton in self.skeletons:
            try:
                content = Path(skeleton.file_path).read_text(encoding="utf-8", errors="replace")
                if indicator in content:
                    matches.append(skeleton.file_path)
            except OSError:
                pass
        return matches

    def summary(self) -> dict[str, Any]:
        return {
            "total_files": len(self.skeletons),
            "total_functions": sum(len(s.functions) for s in self.skeletons),
            "total_imports": sum(len(s.imports) for s in self.skeletons),
            "unique_modules_imported": list(self._import_map.keys()),
        }


class CodebaseIndexer:
    """
    Orchestrates Module 1:
      1. Walks the codebase with Tree-sitter
      2. Optionally pushes embeddings to ChromaDB
      3. Returns a CodeIndex for use by Modules 3 and 4
    """

    def __init__(self, use_vector_db: bool = False):
        from modules.ingestion.tree_sitter_parser import TreeSitterParser
        self.parser = TreeSitterParser()
        self.use_vector_db = use_vector_db

    async def index(self, codebase_path: Path) -> CodeIndex:
        if not codebase_path.exists():
            raise FileNotFoundError(f"Codebase path does not exist: {codebase_path}")

        logger.info("Indexing codebase: %s", codebase_path)
        skeletons = self.parser.parse_directory(codebase_path)
        index = CodeIndex(skeletons)

        if self.use_vector_db:
            await self._push_to_chroma(index)

        summary = index.summary()
        logger.info(
            "Index built: %d files, %d functions, %d unique imports",
            summary["total_files"],
            summary["total_functions"],
            len(summary["unique_modules_imported"]),
        )
        return index

    async def _push_to_chroma(self, index: CodeIndex):
        """
        Pushes function-level embeddings to ChromaDB for semantic search.
        Uses Ollama's nomic-embed-text model running on the GPU VM.
        """
        try:
            import chromadb
            from api.config import settings

            client = chromadb.PersistentClient(path=settings.chromadb_persist_path)
            collection = client.get_or_create_collection(index.collection_name)

            docs, ids, metas = [], [], []
            for skeleton in index.skeletons:
                for func in skeleton.functions:
                    doc_id = f"{func.file_path}::{func.name}::{func.line}"
                    doc_text = (
                        f"file: {func.file_path}\n"
                        f"function: {func.name}({', '.join(func.parameters)})\n"
                        f"decorators: {', '.join(func.decorators)}"
                    )
                    docs.append(doc_text)
                    ids.append(doc_id)
                    metas.append({"file": func.file_path, "line": func.line})

            if docs:
                collection.upsert(documents=docs, ids=ids, metadatas=metas)
                logger.info("Pushed %d function entries to ChromaDB", len(docs))

        except ImportError:
            logger.warning("chromadb not installed, skipping vector push")
