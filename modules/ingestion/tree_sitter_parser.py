"""
Module 1 — Tree-sitter AST Parser

Extracts a lightweight structural skeleton from Python source files:
- Function signatures (name, parameters, decorators)
- Import maps (what packages are imported, as what aliases)
- Class definitions

This skeleton is stored in the vector DB to allow token-efficient
navigation without loading raw source into the LLM context window.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ImportRecord:
    module: str
    alias: Optional[str]
    symbols: list[str] = field(default_factory=list)
    line: int = 0


@dataclass
class FunctionSignature:
    name: str
    parameters: list[str]
    decorators: list[str]
    file_path: str
    line: int
    docstring: Optional[str] = None


@dataclass
class FileSkeletonMap:
    """Token-optimised structural snapshot of a single Python file."""

    file_path: str
    imports: list[ImportRecord]
    functions: list[FunctionSignature]
    classes: list[str]
    raw_size_bytes: int


class TreeSitterParser:
    """
    Parses Python source files using tree-sitter to extract structural metadata.
    The grammar is lazily initialised on first use.
    """

    def __init__(self):
        self._parser = None
        self._language = None

    def _ensure_parser(self):
        if self._parser is not None:
            return
        try:
            import tree_sitter_python as tspython
            from tree_sitter import Language, Parser

            self._language = Language(tspython.language())
            self._parser = Parser(self._language)
            logger.debug("Tree-sitter Python parser initialised")
        except ImportError as exc:
            raise RuntimeError(
                "tree-sitter-python is not installed. Run: pip install tree-sitter tree-sitter-python"
            ) from exc

    def parse_file(self, path: Path) -> FileSkeletonMap:
        self._ensure_parser()
        source = path.read_bytes()
        tree = self._parser.parse(source)
        source_str = source.decode("utf-8", errors="replace")

        imports = self._extract_imports(tree.root_node, source_str)
        functions = self._extract_functions(tree.root_node, source_str, str(path))
        classes = self._extract_class_names(tree.root_node, source_str)

        return FileSkeletonMap(
            file_path=str(path),
            imports=imports,
            functions=functions,
            classes=classes,
            raw_size_bytes=len(source),
        )

    def parse_directory(self, root: Path, glob: str = "**/*.py") -> list[FileSkeletonMap]:
        skeletons = []
        for py_file in sorted(root.glob(glob)):
            try:
                skeletons.append(self.parse_file(py_file))
            except Exception as exc:
                logger.warning("Skipping %s: %s", py_file, exc)
        logger.info("Parsed %d Python files under %s", len(skeletons), root)
        return skeletons

    # ── Private helpers ───────────────────────────────────────────────────────

    def _node_text(self, node, source: str) -> str:
        return source[node.start_byte:node.end_byte]

    def _extract_imports(self, root_node, source: str) -> list[ImportRecord]:
        imports: list[ImportRecord] = []
        for node in root_node.children:
            if node.type == "import_statement":
                for child in node.named_children:
                    if child.type in ("dotted_name", "aliased_import"):
                        module = self._node_text(child, source).split(" as ")[0].strip()
                        alias = None
                        if " as " in self._node_text(child, source):
                            alias = self._node_text(child, source).split(" as ")[1].strip()
                        imports.append(ImportRecord(module=module, alias=alias, line=node.start_point[0]))

            elif node.type == "import_from_statement":
                module_node = node.child_by_field_name("module_name")
                module = self._node_text(module_node, source) if module_node else "?"
                symbols = []
                for child in node.named_children:
                    if child.type in ("dotted_name", "aliased_import") and child != module_node:
                        symbols.append(self._node_text(child, source).split(" as ")[0].strip())
                imports.append(ImportRecord(module=module, symbols=symbols, line=node.start_point[0]))
        return imports

    def _extract_functions(self, root_node, source: str, file_path: str) -> list[FunctionSignature]:
        functions = []
        self._walk_functions(root_node, source, file_path, functions)
        return functions

    def _walk_functions(self, node, source: str, file_path: str, acc: list):
        if node.type in ("function_definition", "async_function_definition"):
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            name = self._node_text(name_node, source) if name_node else "?"
            params = []
            if params_node:
                for p in params_node.named_children:
                    params.append(self._node_text(p, source))
            decorators = []
            for sibling in (node.parent.children if node.parent else []):
                if sibling.type == "decorator" and sibling.end_point[0] < node.start_point[0]:
                    decorators.append(self._node_text(sibling, source))
            acc.append(FunctionSignature(
                name=name,
                parameters=params,
                decorators=decorators,
                file_path=file_path,
                line=node.start_point[0],
            ))
        for child in node.children:
            self._walk_functions(child, source, file_path, acc)

    def _extract_class_names(self, root_node, source: str) -> list[str]:
        names = []
        for node in root_node.children:
            if node.type == "class_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    names.append(self._node_text(name_node, source))
        return names
