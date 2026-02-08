"""
ShieldIaC — HCL File Parser Utility

Provides enhanced HCL parsing capabilities beyond the basic parser
in the Terraform scanner.
"""
from __future__ import annotations

import json
import re
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class HCLParser:
    """Parse HCL (HashiCorp Configuration Language) files into Python dicts.

    This is a lightweight parser suitable for security scanning.
    For full fidelity, use python-hcl2 library.
    """

    def parse(self, content: str) -> Dict[str, Any]:
        """Parse HCL content into a structured dictionary.

        Returns a dict with keys: resource, data, variable, output, locals, provider, module.
        """
        result: Dict[str, Any] = {
            "resource": {},
            "data": {},
            "variable": {},
            "output": {},
            "locals": {},
            "provider": {},
            "module": {},
        }

        # Remove comments
        content = self._strip_comments(content)

        # Extract top-level blocks
        blocks = self._extract_top_level_blocks(content)

        for block_type, labels, body, line_num in blocks:
            parsed_body = self._parse_body(body)

            if block_type == "resource" and len(labels) >= 2:
                resource_type, resource_name = labels[0], labels[1]
                result["resource"].setdefault(resource_type, {})
                result["resource"][resource_type][resource_name] = parsed_body
                parsed_body["__line__"] = line_num

            elif block_type == "data" and len(labels) >= 2:
                data_type, data_name = labels[0], labels[1]
                result["data"].setdefault(data_type, {})
                result["data"][data_type][data_name] = parsed_body

            elif block_type == "variable" and labels:
                result["variable"][labels[0]] = parsed_body

            elif block_type == "output" and labels:
                result["output"][labels[0]] = parsed_body

            elif block_type == "provider" and labels:
                result["provider"][labels[0]] = parsed_body

            elif block_type == "module" and labels:
                result["module"][labels[0]] = parsed_body

            elif block_type == "locals":
                result["locals"].update(parsed_body)

        return result

    def _strip_comments(self, content: str) -> str:
        """Remove HCL comments (# and // for single-line, /* */ for multi-line)."""
        # Multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # Single-line comments
        lines = []
        for line in content.split('\n'):
            # Remove # and // comments (but not inside strings)
            in_string = False
            result_chars = []
            i = 0
            while i < len(line):
                ch = line[i]
                if ch == '"' and (i == 0 or line[i-1] != '\\'):
                    in_string = not in_string
                    result_chars.append(ch)
                elif not in_string and ch == '#':
                    break
                elif not in_string and ch == '/' and i + 1 < len(line) and line[i+1] == '/':
                    break
                else:
                    result_chars.append(ch)
                i += 1
            lines.append(''.join(result_chars))
        return '\n'.join(lines)

    def _extract_top_level_blocks(self, content: str) -> List[Tuple[str, List[str], str, int]]:
        """Extract top-level blocks as (type, labels, body, line_number)."""
        blocks = []
        pattern = re.compile(
            r'^(\w+)\s+((?:"[^"]*"\s*)*)\{',
            re.MULTILINE,
        )

        for match in pattern.finditer(content):
            block_type = match.group(1)
            labels_str = match.group(2).strip()
            labels = re.findall(r'"([^"]*)"', labels_str)

            line_num = content[:match.start()].count('\n') + 1
            brace_start = match.end() - 1
            body = self._extract_brace_content(content, brace_start)
            blocks.append((block_type, labels, body, line_num))

        return blocks

    def _extract_brace_content(self, content: str, start: int) -> str:
        """Extract content between matching braces."""
        depth = 0
        i = start
        in_string = False
        while i < len(content):
            ch = content[i]
            if ch == '"' and (i == 0 or content[i-1] != '\\'):
                in_string = not in_string
            elif not in_string:
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return content[start + 1:i]
            i += 1
        return content[start + 1:]

    def _parse_body(self, body: str) -> Dict[str, Any]:
        """Parse a block body into attributes."""
        attrs: Dict[str, Any] = {}
        lines = body.split('\n')
        i = 0

        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue

            # Key = value
            eq_match = re.match(r'(\w+)\s*=\s*(.*)', line)
            if eq_match:
                key = eq_match.group(1)
                val_str = eq_match.group(2).strip()
                attrs[key] = self._parse_value(val_str)
                i += 1
                continue

            # Nested block
            block_match = re.match(r'(\w+)\s*(?:"[^"]*"\s*)?\{', line)
            if block_match:
                key = block_match.group(1)
                nested = self._collect_nested_from_lines(lines, i)
                attrs[key] = self._parse_body(nested)
                # Skip past nested block
                depth = 0
                while i < len(lines):
                    for ch in lines[i]:
                        if ch == '{': depth += 1
                        elif ch == '}': depth -= 1
                    if depth <= 0 and i > 0:
                        break
                    i += 1
                i += 1
                continue

            i += 1

        return attrs

    def _collect_nested_from_lines(self, lines: List[str], start: int) -> str:
        depth = 0
        result = []
        for i in range(start, len(lines)):
            for ch in lines[i]:
                if ch == '{': depth += 1
                elif ch == '}': depth -= 1
            if depth >= 1 and i > start:
                result.append(lines[i])
            if depth == 0 and i > start:
                break
        return '\n'.join(result)

    def _parse_value(self, val: str) -> Any:
        val = val.strip().rstrip(',')
        if val == 'true': return True
        if val == 'false': return False
        if val == 'null': return None
        try:
            if '.' in val: return float(val)
            return int(val)
        except ValueError:
            pass
        if val.startswith('"') and val.endswith('"'):
            return val[1:-1]
        if val.startswith('['):
            return self._parse_list(val)
        if val.startswith('{'):
            return self._parse_map(val)
        return val

    def _parse_list(self, val: str) -> List:
        inner = val.strip('[]').strip()
        if not inner:
            return []
        items = []
        for item in inner.split(','):
            item = item.strip()
            if item:
                items.append(self._parse_value(item))
        return items

    def _parse_map(self, val: str) -> Dict:
        inner = val.strip('{}').strip()
        result = {}
        for pair in inner.split(','):
            if '=' in pair:
                k, v = pair.split('=', 1)
                result[k.strip().strip('"')] = self._parse_value(v.strip())
        return result


def parse_hcl(content: str) -> Dict[str, Any]:
    """Convenience function to parse HCL content."""
    return HCLParser().parse(content)
