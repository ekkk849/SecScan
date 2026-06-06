# parser.py
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional


@dataclass
class VulnerabilityFinding:
    file_name: str
    vuln_type: str
    severity: str
    table: str
    column: Optional[str]
    line_number: int
    code_snippet: str
    description: str
    recommendation: str


class SQLParser:
    _CONCAT_PATTERNS = [
        re.compile(r'"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+', re.IGNORECASE),
        re.compile(r'"[^"]*(?:WHERE|AND|OR|SET|LIKE)[^"]*"\s*\+\s*\w', re.IGNORECASE),
        re.compile(r'\+\s*\w+\s*\+\s*"[^"]*(?:WHERE|AND|LIKE|ORDER)[^"]*"', re.IGNORECASE),
        re.compile(r'"[^"]*=\s*\'?"\s*\+\s*\w+\b', re.IGNORECASE),
        re.compile(r'\$"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|SET)[^"]*\{', re.IGNORECASE),
        re.compile(r'[Ss]tring\.Format\s*\(\s*"[^"]*(?:SELECT|WHERE|FROM)[^"]*\{[0-9]', re.IGNORECASE),
        re.compile(r'"[^"]*ORDER\s+BY\s*"\s*\+\s*\w', re.IGNORECASE),
        re.compile(r'LIKE\s+\'%"\s*\+\s*\w', re.IGNORECASE),
    ]

    _PARAM_PATTERNS = [
        re.compile(r'\.Parameters\.AddWithValue\s*\(', re.IGNORECASE),
        re.compile(r'\.Parameters\.Add\s*\(', re.IGNORECASE),
        re.compile(r'new\s+SqlParameter\s*\(', re.IGNORECASE),
    ]
    _NAMED_PARAM = re.compile(r'@[A-Za-z]\w+')

    # Captures: FROM/JOIN TableName [AS] alias
    # Alias group is optional; handles single-char aliases like p, o, c
    _TABLE_RE = re.compile(
        r'\b(?:FROM|JOIN)\s+(\w+)\s*(?:(?:AS\s+)?([A-Za-z_]\w*))?',
        re.IGNORECASE
    )
    _COL_RE   = re.compile(r'\b([A-Za-z]\w*)\.([A-Za-z]\w*)\b')
    _JOIN_RE  = re.compile(r'\b(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)\b')

    _SKIP_WORDS = {
        'ON','WHERE','SET','AND','OR','JOIN','LEFT','RIGHT','INNER','OUTER','CROSS',
        'FULL','AS','BY','INTO','var','new','using','string','int','void','return',
        'public','private','protected','static','class','SELECT','FROM','NULL',
        'COUNT','SUM','AVG','MAX','MIN','CAST','TOP','IS','NOT','IN','EXISTS',
    }
    _NOISE_ALIASES = {
        'cmd','conn','tx','adapter','dt','cursor','reader','command',
        'connection','transaction','da','dr','sql','query','sc','sp',
    }

    def __init__(self, csharp_code: str, file_name: str = "upload.cs"):
        self.code      = csharp_code
        self.file_name = file_name
        self.lines     = csharp_code.splitlines()
        self.tables:            dict[str, str]  = {}
        self.columns:           dict[str, set]  = defaultdict(set)
        self.joins:             list            = []
        self.column_types:      dict[str, dict] = defaultdict(dict)
        self.db_type:           str             = "sqlite"
        self.findings:          list            = []
        self.safe_columns:      dict[str, set]  = defaultdict(set)
        self.vulnerable_columns:dict[str, set]  = defaultdict(set)

    def parse(self) -> dict:
        # Scan raw source — catches ALL table refs even in concat chains
        self._parse_tables_raw()
        self._parse_columns_raw()
        self._parse_joins_raw()
        self._detect_db_type()
        self._scan_vulnerabilities()
        self._scan_parameterization()
        self._infer_column_types()

        return {
            "tables":             {k: v for k, v in self.tables.items() if k == v},
            "columns":            {k: sorted(v) for k, v in self.columns.items()},
            "joins":              [list(j) for j in self.joins],
            "column_types":       {t: dict(c) for t, c in self.column_types.items()},
            "db_type":            self.db_type,
            "findings":           [self._f2d(f) for f in self.findings],
            "safe_columns":       {t: sorted(c) for t, c in self.safe_columns.items()},
            "vulnerable_columns": {t: sorted(c) for t, c in self.vulnerable_columns.items()},
        }

    def extract_sql_blocks(self) -> list[str]:
        """Return stitched SQL strings for display in inject page."""
        results = []
        seen = set()
        cmd_re = re.compile(
            r'cmd(?:\.CommandText)?\s*=|new\s+SqlCommand\s*\(', re.IGNORECASE
        )
        str_seg = re.compile(r'@?"((?:[^"\\]|\\.)*?)"')

        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            if not cmd_re.search(line):
                i += 1
                continue
            # Collect continuation lines
            block_lines = [line]
            j = i + 1
            while j < len(self.lines) and j < i + 20:
                next_line = self.lines[j].lstrip()
                prev = block_lines[-1].rstrip()
                if (prev.endswith('+') or prev.endswith(',') or
                        next_line.startswith('"') or next_line.startswith('+') or
                        next_line.startswith('$"')):
                    block_lines.append(self.lines[j])
                    j += 1
                    if (self.lines[j-1].rstrip().endswith(';') and
                            not self.lines[j-1].rstrip().endswith('"+') and
                            not self.lines[j-1].rstrip().endswith('"+')):
                        break
                else:
                    break

            full = ' '.join(block_lines)
            segs = str_seg.findall(full)
            interp = re.findall(r'\$"((?:[^"\\]|\\.)*?)"', full)
            all_segs = segs + interp
            if all_segs:
                stitched = ' '.join(s.strip() for s in all_segs if s.strip())
                stitched = stitched.replace('\\n', ' ').replace('\\t', ' ')
                if (re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|FROM)\b', stitched, re.IGNORECASE)
                        and stitched not in seen):
                    seen.add(stitched)
                    results.append(stitched)
            i = j if j > i + 1 else i + 1

        return results

    # Methods we should never treat as column names
    _SKIP_METHODS = {
        'CommandText','Connection','Transaction','Parameters','ExecuteNonQuery',
        'ExecuteReader','ExecuteScalar','AddWithValue','BeginTransaction',
        'Open','Close','Commit','Rollback','Fill','Length','ToString',
        'Format','Contains','Replace','Trim','Split',
    }

    # ── Method-body extraction ────────────────────────────────────────────
    def _iter_method_bodies(self):
        """Yield (method_name, start_line, body_str) for every method in the file."""
        method_re = re.compile(
            r'(?:public|private|protected|internal)\s+\S+\s+(\w+)\s*\([^)]*\)\s*\{',
        )
        for m in method_re.finditer(self.code):
            depth = 1; pos = m.end()
            while pos < len(self.code) and depth > 0:
                if self.code[pos] == '{': depth += 1
                elif self.code[pos] == '}': depth -= 1
                pos += 1
            body = self.code[m.end():pos - 1]
            line_num = self.code[:m.start()].count('\n') + 1
            yield m.group(1), line_num, body

    def _build_local_aliases(self, text: str) -> dict[str, str]:
        """
        Build alias -> real_table map for a single SQL block / method body.
        Single-char aliases (p, o, c …) are valid here because we scope per-method,
        so alias 'c' for Categories in one method won't bleed into another.
        """
        aliases: dict[str, str] = {}
        for m in self._TABLE_RE.finditer(text):
            table = m.group(1)
            alias = m.group(2)
            if table.upper() in self._SKIP_WORDS or len(table) <= 1:
                continue
            aliases[table] = table
            if alias and alias.upper() not in self._SKIP_WORDS:
                aliases[alias] = table
        return aliases

    # ── Table / column / join parsing ─────────────────────────────────────
    def _parse_tables_raw(self):
        """
        Global table registry — only real table names (no alias leakage).
        Used for display and for _guess_table_col fallback.
        """
        for m in self._TABLE_RE.finditer(self.code):
            table = m.group(1)
            if table.upper() in self._SKIP_WORDS or len(table) <= 1:
                continue
            self.tables[table] = table
            # Also stash alias in global map for _guess_table_col / _parse_joins_raw
            alias = m.group(2)
            if alias and alias.upper() not in self._SKIP_WORDS:
                self.tables[alias] = table

    def _parse_columns_raw(self):
        """
        Resolve alias.Column references *per method body* so that alias 'c'
        maps to Categories in one method and Customers in another, without collision.
        """
        for _name, _line, body in self._iter_method_bodies():
            local = self._build_local_aliases(body)
            for alias, col in self._COL_RE.findall(body):
                if alias.lower() in self._NOISE_ALIASES:
                    continue
                if col in self._SKIP_METHODS or col.upper() in self._SKIP_WORDS:
                    continue
                if len(col) <= 1:
                    continue
                real = local.get(alias)
                if real:
                    self.columns[real].add(col)

    def _parse_joins_raw(self):
        """Extract JOIN conditions per method to use local alias maps."""
        seen: set = set()
        for _name, _line, body in self._iter_method_bodies():
            local = self._build_local_aliases(body)
            for m in self._JOIN_RE.finditer(body):
                la, lc, ra, rc = m.groups()
                lt = local.get(la)
                rt = local.get(ra)
                if lt and rt and lt != rt:
                    key = (lt, lc, rt, rc)
                    if key not in seen:
                        seen.add(key)
                        self.joins.append(list(key))

    def _detect_db_type(self):
        upper = self.code.upper()
        if any(k in upper for k in ('WAITFOR DELAY','@@VERSION','SCOPE_IDENTITY','TOP 1 ')):
            self.db_type = "sqlserver"

    def _scan_vulnerabilities(self):
        reported = set()
        for line_idx, line in enumerate(self.lines, 1):
            if line_idx in reported:
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue
            for pat in self._CONCAT_PATTERNS:
                if pat.search(line):
                    reported.add(line_idx)
                    table, col = self._guess_table_col(line, line_idx)
                    vuln_type = "interpolated_sql" if ('$"' in line and '{' in line) else "string_concat"
                    if col and table != "unknown":
                        self.vulnerable_columns[table].add(col)
                    self.findings.append(VulnerabilityFinding(
                        file_name    = self.file_name,
                        vuln_type    = vuln_type,
                        severity     = "HIGH",
                        table        = table,
                        column       = col,
                        line_number  = line_idx,
                        code_snippet = stripped[:120],
                        description  = (
                            "C# interpolated string used to build SQL — user input injected directly."
                            if vuln_type == "interpolated_sql" else
                            "SQL query built with string concatenation — user input injected directly."
                        ),
                        recommendation = 'Use cmd.Parameters.AddWithValue("@param", value) instead.',
                    ))
                    break

    def _scan_parameterization(self):
        for method_name, line_num, body in self._iter_method_bodies():
            has_sql    = bool(re.search(r'\b(SELECT|INSERT|UPDATE|DELETE)\b', body, re.IGNORECASE))
            has_params = any(p.search(body) for p in self._PARAM_PATTERNS)
            has_named  = bool(self._NAMED_PARAM.search(body))
            has_concat = any(p.search(body) for p in self._CONCAT_PATTERNS)

            if not has_sql:
                continue

            if (has_params or has_named) and not has_concat:
                # Safe — mark columns using local alias map for this method
                local = self._build_local_aliases(body)
                for alias, col in self._COL_RE.findall(body):
                    if alias.lower() in self._NOISE_ALIASES:
                        continue
                    real = local.get(alias)
                    if real:
                        self.safe_columns[real].add(col)
            elif not has_params and not has_named and not has_concat:
                self.findings.append(VulnerabilityFinding(
                    file_name    = self.file_name,
                    vuln_type    = "no_parameterization",
                    severity     = "MEDIUM",
                    table        = "unknown",
                    column       = None,
                    line_number  = line_num,
                    code_snippet = f"Method: {method_name}()",
                    description  = "SQL method with no detectable parameterization.",
                    recommendation = "Verify parameterized queries or stored procedures are used.",
                ))

    def _infer_column_types(self):
        for table, cols in self.columns.items():
            for col in cols:
                low = col.lower()
                if any(k in low for k in ('date','time','created','modified','updated','expir','birth')):
                    t = "DATE"
                elif low.endswith('id') or low in ('quantity','qty','count','age','year','number','num','floor','stock','duration','quantity'):
                    t = "INTEGER"
                elif any(k in low for k in ('price','amount','total','cost','salary','rate','balance','revenue','dosage')):
                    t = "REAL"
                else:
                    t = "TEXT"
                self.column_types[table][col] = t

    def _guess_table_col(self, line: str, line_idx: int) -> tuple[str, Optional[str]]:
        # Build a local alias map from surrounding context (±8 lines)
        ctx = '\n'.join(self.lines[max(0, line_idx - 8):min(len(self.lines), line_idx + 4)])
        local = self._build_local_aliases(ctx)

        for alias, col in self._COL_RE.findall(line):
            if alias.lower() in self._NOISE_ALIASES:
                continue
            real = local.get(alias) or self.tables.get(alias)
            if real:
                return real, col

        # Fallback: broader context
        for alias, col in self._COL_RE.findall(ctx):
            if alias.lower() in self._NOISE_ALIASES:
                continue
            real = local.get(alias) or self.tables.get(alias)
            if real:
                return real, col

        return "unknown", None

    @staticmethod
    def _f2d(f: VulnerabilityFinding) -> dict:
        return {k: getattr(f, k) for k in f.__dataclass_fields__}
