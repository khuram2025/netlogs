"""
Zentryc Query Language (NQL) Parser

Converts NQL queries into ClickHouse SQL for the syslogs table.

Syntax:
  # Basic field matching
  srcip:10.0.0.1
  action:deny

  # Comparison operators
  dstport:>1024
  severity:<4
  dstport:>=80

  # CIDR notation
  srcip:10.0.0.0/8

  # Wildcard
  srcip:192.168.*

  # Multiple values (OR)
  action:accept|allow|close

  # Negation
  NOT action:allow
  -action:allow

  # Boolean operators (AND has higher precedence than OR)
  srcip:10.0.0.1 AND action:deny
  srcip:10.0.0.1 OR srcip:10.0.0.2
  (srcip:10.0.0.1 OR srcip:10.0.0.2) AND action:deny

  # Text search (in message/raw fields)
  "connection refused"

  # Pipeline aggregation
  action:deny | stats count by srcip | where count > 100 | sort -count | limit 20

Architecture:
  1. Tokenizer: NQL string -> token list
  2. Parser: token list -> AST
  3. Compiler: AST -> ClickHouse SQL (reuses ClickHouseClient._build_field_condition)
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Any, Dict

logger = logging.getLogger(__name__)


# ============================================================
# Token types
# ============================================================

class TokenType:
    FIELD_TERM = "FIELD_TERM"      # srcip:10.0.0.1
    TEXT_TERM = "TEXT_TERM"         # "connection refused" or bare words
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    PIPE = "PIPE"                  # |  (pipeline separator)
    PIPELINE_CMD = "PIPELINE_CMD"  # stats, where, sort, limit
    PIPELINE_ARG = "PIPELINE_ARG"  # everything after the command keyword
    EOF = "EOF"


@dataclass
class Token:
    type: str
    value: str
    pos: int = 0  # position in original query for error messages


# ============================================================
# AST node types
# ============================================================

@dataclass
class FieldTermNode:
    """A single field:value filter term."""
    field: str
    value: str
    operator: str = "="   # =, >, <, >=, <=, ~
    negated: bool = False


@dataclass
class TextTermNode:
    """A text search term (searches message/raw)."""
    value: str
    negated: bool = False


@dataclass
class AndNode:
    """AND of two expressions."""
    left: Any
    right: Any


@dataclass
class OrNode:
    """OR of two expressions."""
    left: Any
    right: Any


@dataclass
class NotNode:
    """NOT of an expression."""
    child: Any


@dataclass
class PipelineStage:
    """A pipeline stage: stats, where, sort, or limit."""
    command: str   # stats, where, sort, limit
    args: str      # raw argument string


@dataclass
class NQLQuery:
    """Complete parsed NQL query."""
    filter_ast: Any                         # AST for WHERE clause
    pipeline: List[PipelineStage] = field(default_factory=list)


# ============================================================
# NQL field names (valid fields for the syslogs table)
# ============================================================

VALID_FIELDS = {
    "srcip", "dstip", "srcport", "dstport", "proto", "protocol",
    "action", "severity", "device", "device_ip", "policyname",
    "log_type", "application", "app", "src_zone", "dst_zone",
    "session_end_reason", "threat_id", "message", "raw",
    "facility", "timestamp",
}

# Fields that accept numeric comparisons
NUMERIC_FIELDS = {"srcport", "dstport", "severity", "facility"}

# Pipeline command keywords
PIPELINE_COMMANDS = {"stats", "where", "sort", "limit"}


# ============================================================
# Tokenizer
# ============================================================

class NQLTokenizer:
    """Tokenize NQL query string into a list of tokens."""

    def __init__(self, query: str):
        self.query = query
        self.pos = 0
        self.tokens: List[Token] = []

    def tokenize(self) -> List[Token]:
        """Tokenize the full query. Split on first pipe for pipeline."""
        # Split into filter part and pipeline part
        filter_part, pipeline_parts = self._split_pipeline(self.query)

        # Tokenize the filter part
        self._tokenize_filter(filter_part)

        # Tokenize pipeline parts
        for part in pipeline_parts:
            self.tokens.append(Token(TokenType.PIPE, "|"))
            part = part.strip()
            # Extract command keyword
            cmd_match = re.match(r'(\w+)\s*(.*)', part, re.DOTALL)
            if cmd_match:
                cmd = cmd_match.group(1).lower()
                args = cmd_match.group(2).strip()
                if cmd in PIPELINE_COMMANDS:
                    self.tokens.append(Token(TokenType.PIPELINE_CMD, cmd))
                    if args:
                        self.tokens.append(Token(TokenType.PIPELINE_ARG, args))
                else:
                    raise NQLSyntaxError(
                        f"Unknown pipeline command: '{cmd}'. Valid commands: {', '.join(sorted(PIPELINE_COMMANDS))}"
                    )

        self.tokens.append(Token(TokenType.EOF, ""))
        return self.tokens

    def _split_pipeline(self, query: str) -> Tuple[str, List[str]]:
        """Split query into filter part and pipeline stages.

        The pipe character inside field values (e.g., action:accept|deny)
        should NOT be treated as a pipeline separator. A pipeline pipe is
        preceded by whitespace or is at the start.
        """
        parts = []
        current = []
        i = 0
        in_quotes = False

        while i < len(query):
            ch = query[i]

            if ch == '"':
                in_quotes = not in_quotes
                current.append(ch)
            elif ch == '|' and not in_quotes:
                # Check if this is a pipeline pipe (preceded by space or start)
                # vs value-OR pipe (inside field:val1|val2)
                # A pipeline pipe has whitespace immediately before it
                prev_char = query[i - 1] if i > 0 else ' '
                if prev_char in (' ', '\t') or i == 0:
                    # Pipeline separator
                    parts.append(''.join(current))
                    current = []
                else:
                    current.append(ch)
            else:
                current.append(ch)
            i += 1

        parts.append(''.join(current))
        return parts[0], parts[1:]

    def _tokenize_filter(self, text: str):
        """Tokenize the filter portion of the query."""
        i = 0
        text = text.strip()

        while i < len(text):
            # Skip whitespace
            if text[i] in (' ', '\t'):
                i += 1
                continue

            # Parentheses
            if text[i] == '(':
                self.tokens.append(Token(TokenType.LPAREN, "(", i))
                i += 1
                continue
            if text[i] == ')':
                self.tokens.append(Token(TokenType.RPAREN, ")", i))
                i += 1
                continue

            # Check for AND / OR / NOT keywords
            rest = text[i:]
            kw_match = re.match(r'(AND|OR|NOT)\b', rest, re.IGNORECASE)
            if kw_match:
                kw = kw_match.group(1).upper()
                # Make sure NOT isn't followed by a colon (that would be a field name)
                after = text[i + len(kw):]
                if not after.lstrip().startswith(':'):
                    self.tokens.append(Token(getattr(TokenType, kw), kw, i))
                    i += len(kw)
                    continue

            # Quoted string: "some text"
            if text[i] == '"':
                end = text.index('"', i + 1) if '"' in text[i+1:] else len(text)
                value = text[i+1:end]
                self.tokens.append(Token(TokenType.TEXT_TERM, value, i))
                i = end + 1
                continue

            # Negation prefix: -field:value
            negated = False
            if text[i] == '-' and i + 1 < len(text) and text[i+1] not in (' ', '\t'):
                negated = True
                i += 1

            # field:operator?value  or  bare_word
            term_match = re.match(r'(\w+):(!=|>=|<=|>|<|=|~)?([^\s()]+)', text[i:])
            if term_match:
                field_name = term_match.group(1).lower()
                operator = term_match.group(2) or '='
                value = term_match.group(3)

                if operator == '!=':
                    negated = not negated  # double negation cancels
                    operator = '='

                self.tokens.append(Token(TokenType.FIELD_TERM, f"{field_name}:{operator}:{value}", i))
                # Store parsed components as extra data on the token
                self.tokens[-1]._field = field_name
                self.tokens[-1]._value = value
                self.tokens[-1]._operator = operator
                self.tokens[-1]._negated = negated
                i += term_match.end()
                continue

            # Bare word (text search)
            word_match = re.match(r'[^\s()]+', text[i:])
            if word_match:
                value = word_match.group(0)
                tok = Token(TokenType.TEXT_TERM, value, i)
                tok._negated = negated
                self.tokens.append(tok)
                i += word_match.end()
                continue

            i += 1

    def _is_pipeline_pipe(self, text: str, pos: int) -> bool:
        """Check if pipe at position is a pipeline separator vs OR in field value."""
        before = text[:pos].rstrip()
        return not before or before[-1] in (' ', '\t', ')')


# ============================================================
# Parser (recursive descent)
# ============================================================

class NQLParser:
    """Parse token list into an AST using recursive descent.

    Grammar:
      query     -> or_expr
      or_expr   -> and_expr (OR and_expr)*
      and_expr  -> not_expr (AND? not_expr)*    // implicit AND
      not_expr  -> NOT? primary
      primary   -> LPAREN or_expr RPAREN | field_term | text_term
    """

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def parse(self) -> NQLQuery:
        """Parse tokens into an NQLQuery with filter AST and pipeline stages."""
        # Parse filter expression
        if self.current().type in (TokenType.EOF, TokenType.PIPE):
            filter_ast = None
        else:
            filter_ast = self._parse_or()

        # Parse pipeline stages
        pipeline = []
        while self.current().type == TokenType.PIPE:
            self.advance()  # consume |
            if self.current().type != TokenType.PIPELINE_CMD:
                raise NQLSyntaxError("Expected pipeline command after '|'")
            cmd = self.current().value
            self.advance()
            args = ""
            if self.current().type == TokenType.PIPELINE_ARG:
                args = self.current().value
                self.advance()
            pipeline.append(PipelineStage(command=cmd, args=args))

        if self.current().type != TokenType.EOF:
            raise NQLSyntaxError(
                f"Unexpected token: '{self.current().value}' at position {self.current().pos}"
            )

        return NQLQuery(filter_ast=filter_ast, pipeline=pipeline)

    def current(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return Token(TokenType.EOF, "")

    def advance(self) -> Token:
        tok = self.current()
        self.pos += 1
        return tok

    def _parse_or(self):
        left = self._parse_and()
        while self.current().type == TokenType.OR:
            self.advance()
            right = self._parse_and()
            left = OrNode(left, right)
        return left

    def _parse_and(self):
        left = self._parse_not()
        while True:
            cur = self.current()
            if cur.type == TokenType.AND:
                self.advance()
                right = self._parse_not()
                left = AndNode(left, right)
            elif cur.type in (TokenType.FIELD_TERM, TokenType.TEXT_TERM,
                             TokenType.NOT, TokenType.LPAREN):
                # Implicit AND
                right = self._parse_not()
                left = AndNode(left, right)
            else:
                break
        return left

    def _parse_not(self):
        if self.current().type == TokenType.NOT:
            self.advance()
            child = self._parse_primary()
            return NotNode(child)
        return self._parse_primary()

    def _parse_primary(self):
        tok = self.current()

        if tok.type == TokenType.LPAREN:
            self.advance()
            node = self._parse_or()
            if self.current().type != TokenType.RPAREN:
                raise NQLSyntaxError(
                    f"Expected closing parenthesis, got '{self.current().value}'"
                )
            self.advance()
            return node

        if tok.type == TokenType.FIELD_TERM:
            self.advance()
            return FieldTermNode(
                field=tok._field,
                value=tok._value,
                operator=tok._operator,
                negated=tok._negated,
            )

        if tok.type == TokenType.TEXT_TERM:
            self.advance()
            return TextTermNode(value=tok.value, negated=getattr(tok, '_negated', False))

        raise NQLSyntaxError(
            f"Unexpected token: '{tok.value}' (type={tok.type}) at position {tok.pos}"
        )


# ============================================================
# Compiler: AST -> ClickHouse SQL
# ============================================================

class NQLCompiler:
    """Compile NQL AST into ClickHouse SQL components."""

    def __init__(self):
        # Import ClickHouseClient lazily to avoid circular imports
        from ..db.clickhouse import ClickHouseClient
        self.ch = ClickHouseClient

    def compile(self, query: NQLQuery) -> Dict[str, Any]:
        """Compile NQLQuery into SQL components.

        Returns:
            {
                "where": str,          # WHERE clause SQL
                "is_aggregate": bool,  # Whether this is an aggregate query
                "select": str,         # SELECT clause (for aggregate queries)
                "group_by": str,       # GROUP BY clause
                "having": str,         # HAVING clause (from pipeline 'where')
                "order_by": str,       # ORDER BY clause
                "limit": int,          # LIMIT value
            }
        """
        result = {
            "where": "1=1",
            "is_aggregate": False,
            "select": None,
            "group_by": None,
            "having": None,
            "order_by": None,
            "limit": None,
        }

        # Compile filter AST to WHERE
        if query.filter_ast is not None:
            result["where"] = self._compile_node(query.filter_ast)

        # Compile pipeline stages
        for stage in query.pipeline:
            self._compile_pipeline_stage(stage, result)

        return result

    def _compile_node(self, node) -> str:
        """Recursively compile AST node to SQL."""
        if isinstance(node, FieldTermNode):
            return self._compile_field_term(node)
        elif isinstance(node, TextTermNode):
            return self._compile_text_term(node)
        elif isinstance(node, AndNode):
            left = self._compile_node(node.left)
            right = self._compile_node(node.right)
            return f"({left} AND {right})"
        elif isinstance(node, OrNode):
            left = self._compile_node(node.left)
            right = self._compile_node(node.right)
            return f"({left} OR {right})"
        elif isinstance(node, NotNode):
            child = self._compile_node(node.child)
            return f"NOT ({child})"
        else:
            raise NQLSyntaxError(f"Unknown AST node type: {type(node)}")

    def _compile_field_term(self, node: FieldTermNode) -> str:
        """Compile a field:value term using ClickHouseClient's field condition builder."""
        return self.ch._build_field_condition(
            node.field, node.value, node.negated, node.operator
        )

    def _compile_text_term(self, node: TextTermNode) -> str:
        """Compile a text search term."""
        safe_value = node.value.replace("'", "''")
        if node.negated:
            return f"NOT (message ILIKE '%{safe_value}%' OR raw ILIKE '%{safe_value}%')"
        return f"(message ILIKE '%{safe_value}%' OR raw ILIKE '%{safe_value}%')"

    def _compile_pipeline_stage(self, stage: PipelineStage, result: Dict):
        """Compile a pipeline stage into SQL components."""
        if stage.command == "stats":
            self._compile_stats(stage.args, result)
        elif stage.command == "where":
            self._compile_pipeline_where(stage.args, result)
        elif stage.command == "sort":
            self._compile_sort(stage.args, result)
        elif stage.command == "limit":
            self._compile_limit(stage.args, result)

    def _compile_stats(self, args: str, result: Dict):
        """Parse: stats count by srcip  or  stats count as total by srcip, dstip"""
        result["is_aggregate"] = True

        # Pattern: stats <agg_func> [as alias] by <field1>[, field2, ...]
        match = re.match(
            r'(count|sum|avg|min|max|uniq|uniqExact)(?:\((\w*)\))?\s*(?:as\s+(\w+))?\s+by\s+(.+)',
            args.strip(), re.IGNORECASE
        )
        if not match:
            # Simple count without group by
            count_match = re.match(r'(count|sum|avg|min|max|uniq|uniqExact)(?:\((\w*)\))?', args.strip(), re.IGNORECASE)
            if count_match:
                func = count_match.group(1).lower()
                col = count_match.group(2) or ""
                alias = "value"
                if func == "count":
                    result["select"] = f"count() as {alias}"
                else:
                    result["select"] = f"{func}({col}) as {alias}"
                return
            raise NQLSyntaxError(
                f"Invalid stats syntax: '{args}'. Expected: stats count by field"
            )

        func = match.group(1).lower()
        col = match.group(2) or ""
        alias = match.group(3) or func
        group_fields = [f.strip() for f in match.group(4).split(',')]

        # Validate group_by fields
        for gf in group_fields:
            if gf.lower() not in VALID_FIELDS and gf != "timestamp":
                raise NQLSyntaxError(f"Invalid field in group by: '{gf}'")

        group_by_str = ", ".join(group_fields)

        if func == "count":
            select_agg = f"count() as {alias}"
        elif func in ("uniq", "uniqExact"):
            select_agg = f"{func}({col or group_fields[0]}) as {alias}"
        else:
            if not col:
                raise NQLSyntaxError(f"{func}() requires a column name, e.g., {func}(bytes_sent)")
            select_agg = f"{func}({col}) as {alias}"

        result["select"] = f"{group_by_str}, {select_agg}"
        result["group_by"] = group_by_str

    def _compile_pipeline_where(self, args: str, result: Dict):
        """Parse: where count > 100"""
        # Simple comparison: field op value
        match = re.match(r'(\w+)\s*(>=|<=|!=|>|<|=)\s*(\S+)', args.strip())
        if not match:
            raise NQLSyntaxError(f"Invalid where syntax: '{args}'. Expected: where field > value")

        field_name = match.group(1)
        op = match.group(2)
        value = match.group(3)

        result["having"] = f"{field_name} {op} {value}"

    def _compile_sort(self, args: str, result: Dict):
        """Parse: sort -count (desc) or sort count (asc) or sort srcip, -count"""
        parts = [p.strip() for p in args.split(',')]
        order_parts = []
        for part in parts:
            if part.startswith('-'):
                order_parts.append(f"{part[1:]} DESC")
            elif part.startswith('+'):
                order_parts.append(f"{part[1:]} ASC")
            else:
                order_parts.append(f"{part} ASC")
        result["order_by"] = ", ".join(order_parts)

    def _compile_limit(self, args: str, result: Dict):
        """Parse: limit 20"""
        try:
            result["limit"] = min(int(args.strip()), 10000)
        except ValueError:
            raise NQLSyntaxError(f"Invalid limit value: '{args}'. Expected a number.")


# ============================================================
# Error class
# ============================================================

class NQLSyntaxError(Exception):
    """Raised when NQL query has syntax errors."""
    pass


# ============================================================
# Public API
# ============================================================

def parse_nql(query_text: str) -> NQLQuery:
    """Parse an NQL query string into an NQLQuery AST.

    Args:
        query_text: The NQL query string

    Returns:
        NQLQuery with filter_ast and pipeline stages

    Raises:
        NQLSyntaxError: If the query has syntax errors
    """
    if not query_text or not query_text.strip():
        return NQLQuery(filter_ast=None, pipeline=[])

    tokenizer = NQLTokenizer(query_text.strip())
    tokens = tokenizer.tokenize()
    parser = NQLParser(tokens)
    return parser.parse()


def compile_nql(query_text: str) -> Dict[str, Any]:
    """Parse and compile an NQL query to SQL components.

    Args:
        query_text: The NQL query string

    Returns:
        Dict with: where, is_aggregate, select, group_by, having, order_by, limit

    Raises:
        NQLSyntaxError: If the query has syntax errors
    """
    ast = parse_nql(query_text)
    compiler = NQLCompiler()
    return compiler.compile(ast)


def nql_to_clickhouse(
    query_text: str,
    table: str = "syslogs",
    time_filter: str = None,
    default_limit: int = 100,
    default_offset: int = 0,
    columns: str = None,
) -> str:
    """Convert an NQL query string to a complete ClickHouse SQL query.

    Args:
        query_text: The NQL query string
        table: ClickHouse table name
        time_filter: Pre-built time filter for PREWHERE
        default_limit: Default LIMIT if not specified in pipeline
        default_offset: OFFSET value
        columns: Column list for SELECT (ignored for aggregate queries)

    Returns:
        Complete ClickHouse SQL query string

    Raises:
        NQLSyntaxError: If the query has syntax errors
    """
    compiled = compile_nql(query_text)

    prewhere = f"PREWHERE {time_filter}" if time_filter else ""
    where = f"WHERE {compiled['where']}"

    if compiled["is_aggregate"]:
        select = compiled["select"] or "count() as count"
        group_by = f"GROUP BY {compiled['group_by']}" if compiled["group_by"] else ""
        having = f"HAVING {compiled['having']}" if compiled["having"] else ""
        order_by = f"ORDER BY {compiled['order_by']}" if compiled["order_by"] else ""
        limit_val = compiled["limit"] or default_limit
        limit = f"LIMIT {limit_val}"

        return f"""SELECT {select}
FROM {table}
{prewhere}
{where}
{group_by}
{having}
{order_by}
{limit}""".strip()

    else:
        select = columns or "*"
        order_by = f"ORDER BY {compiled['order_by']}" if compiled["order_by"] else "ORDER BY timestamp DESC"
        limit_val = compiled["limit"] or default_limit
        limit = f"LIMIT {limit_val} OFFSET {default_offset}"

        return f"""SELECT {select}
FROM {table}
{prewhere}
{where}
{order_by}
{limit}""".strip()


def validate_nql(query_text: str) -> Tuple[bool, Optional[str]]:
    """Validate an NQL query without executing it.

    Returns:
        (is_valid, error_message) - error_message is None if valid
    """
    try:
        compile_nql(query_text)
        return True, None
    except NQLSyntaxError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


# Field metadata for autocomplete
FIELD_METADATA = {
    "srcip": {"type": "ip", "description": "Source IP address"},
    "dstip": {"type": "ip", "description": "Destination IP address"},
    "srcport": {"type": "number", "description": "Source port"},
    "dstport": {"type": "number", "description": "Destination port"},
    "proto": {"type": "string", "description": "Protocol number"},
    "protocol": {"type": "string", "description": "Protocol name (alias for proto)"},
    "action": {"type": "string", "description": "Firewall action (accept, deny, drop, close, timeout)"},
    "severity": {"type": "number", "description": "Syslog severity (0=Emergency, 7=Debug)"},
    "device": {"type": "ip", "description": "Device IP (alias for device_ip)"},
    "device_ip": {"type": "ip", "description": "Device IP address"},
    "policyname": {"type": "string", "description": "Firewall policy/rule name"},
    "log_type": {"type": "string", "description": "Log type (traffic, utm, event)"},
    "application": {"type": "string", "description": "Application name"},
    "src_zone": {"type": "string", "description": "Source zone"},
    "dst_zone": {"type": "string", "description": "Destination zone"},
    "session_end_reason": {"type": "string", "description": "Session end reason"},
    "threat_id": {"type": "string", "description": "Threat/IPS signature ID"},
    "message": {"type": "text", "description": "Log message (supports ~ for contains)"},
}
