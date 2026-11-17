"""Dependency-free terminal rendering of the common Markdown subset."""

import re

SGR = re.compile(r"\x1b\[[0-9;]*m")
INLINE = re.compile(r"(`[^`]+`|\*\*.+?\*\*|__.+?__|(?<!\*)\*[^*]+\*(?!\*)|\[[^\]]+\]\([^)]+\))")
#: ``<br>``/``<br/>``/``<br />`` are the one HTML tag models use inside tables.
BR = re.compile(r"<br\s*/?>", re.IGNORECASE)

#: Preferred reading width in columns, unless the terminal is narrower.
DEFAULT_READING_WIDTH = 100
#: Never render narrower than this even on a tiny terminal.
MIN_READING_WIDTH = 20
#: Heading level → SGR codes applied to the heading text. Structure only
#: (bold/underline): the palette keeps a single accent, so a heading is not
#: painted in a colour of its own.
HEADINGS = {1: "1;4", 2: "1"}


def _style(text, code, no_color):
    return text if no_color else f"\x1b[{code}m{text}\x1b[0m"


def _visible(text: str) -> int:
    """Length of ``text`` as the terminal shows it, ignoring ANSI escapes."""
    return len(SGR.sub("", text))


def _inline(text, no_color):
    def replace(match):
        value = match.group()
        if value.startswith("`"):
            # Inline code is an accent, not a highlighter: foreground only, no
            # bright background block behind every command in a paragraph.
            return _style(value[1:-1], "38;2;125;207;255", no_color)
        if value.startswith(("**", "__")):
            return _style(value[2:-2], "1", no_color)
        if value.startswith("*"):
            return _style(value[1:-1], "3", no_color)
        label, url = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", value).groups()
        return f"{label} ({url})"
    return INLINE.sub(replace, text)


def _wrap(text, width, indent=""):
    """Wrap ``text`` on word boundaries, keeping ANSI escapes intact.

    Words are measured after stripping SGR sequences so styled text wraps at the
    same visual column as plain text. Long single tokens are never split.
    """
    words = text.split()
    if not words:
        return [indent + text] if text else [""]
    available = max(1, width - _visible(indent))
    lines = []
    current = ""
    for word in words:
        candidate = word if not current else current + " " + word
        if current and _visible(candidate) > available:
            lines.append(indent + current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(indent + current)
    return lines


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _table(rows, width, no_color):
    """Render a pipe table that always fits ``width``.

    ``<br>`` inside a cell starts a new physical line *within* the cell, so the
    row stays a single logical row. Cells wider than their share are clipped
    with ``…`` instead of overflowing or being silently lost.
    """
    parsed = []
    for row in rows:
        cells = []
        for raw in row.strip().strip("|").split("|"):
            parts = [_inline(part.strip(), True) for part in BR.sub("\n", raw.strip()).split("\n")]
            cells.append(parts or [""])
        parsed.append(cells)
    # Drop the ``| --- | --- |`` separator: every cell a single dashed line.
    parsed = [
        row for row in parsed
        if not all(len(cell) == 1 and re.fullmatch(r":?-{3,}:?", cell[0]) for cell in row)
    ]
    if not parsed:
        return []
    columns = max(len(row) for row in parsed)
    # A row is "| " + " | ".join(cells) + " |": 3 columns + 1 border characters.
    max_cell = max(1, (width - (3 * columns + 1)) // columns)
    rendered = []
    for row in parsed:
        cells = []
        for index in range(columns):
            parts = row[index] if index < len(row) else [""]
            cells.append([_clip(part, max_cell) for part in parts])
        rendered.append(cells)
    sizes = []
    for index in range(columns):
        sizes.append(max(1, max(len(part) for row in rendered for part in row[index])))
    border = "+" + "+".join("-" * (size + 2) for size in sizes) + "+"
    result = [border]
    for index, row in enumerate(rendered):
        height = max(len(cell) for cell in row)
        for line_index in range(height):
            result.append("| " + " | ".join(
                (row[column][line_index] if line_index < len(row[column]) else "").ljust(sizes[column])
                for column in range(columns)
            ) + " |")
        if index == 0:
            result.append(border)
    result.append(border)
    return result


def render_markdown(text: str, *, no_color=False, max_width=None) -> str:
    """Render headings, emphasis, links, lists, fences and pipe tables.

    Preserve literal code (including Markdown punctuation). No HTML, images,
    remote resources, terminal hyperlinks, subprocesses or optional imports.
    ``<br>`` variants become real line breaks (inside a table cell, a break
    within the cell); prose wraps to ``max_width`` columns (100 by default) and
    pipe tables clip long cells with ``…`` so the layout always fits.
    """
    width = max(MIN_READING_WIDTH, int(max_width or DEFAULT_READING_WIDTH))
    # Do not let terminal control bytes supplied by a model alter the screen.
    text = SGR.sub("", str(text)).replace("\r\n", "\n")
    text = "".join(char for char in text if char in "\n\t" or char.isprintable())
    lines = text.splitlines()
    output = []
    index = 0
    fenced = False
    while index < len(lines):
        line = lines[index]
        if line.lstrip().startswith("```"):
            fenced = not fenced
            output.append("  " + "-" * min(width - 2, 40))
        elif fenced:
            output.append("  " + line)
        elif "|" in line and index + 1 < len(lines) and re.fullmatch(r"[\s|:-]+", lines[index + 1]) and "---" in lines[index + 1]:
            rows = [line]
            index += 1
            while index < len(lines) and "|" in lines[index]:
                rows.append(lines[index])
                index += 1
            output.extend(_table(rows, width, no_color))
            continue
        else:
            # ``<br>`` is a real line break outside tables; inside a cell it is
            # handled by ``_table`` so the row is never split in two.
            for segment in BR.sub("\n", line).split("\n"):
                if match := re.match(r"^(#{1,6})\s+(.+)$", segment):
                    output.append(_style(_inline(match[2], no_color), HEADINGS.get(len(match[1]), "1"), no_color))
                elif match := re.match(r"^(\s*)([-*+] |\d+[.)] )(.+)$", segment):
                    # Nesting is structure, not decoration: a sub-list two spaces
                    # deeper keeps two more spaces, so a checklist inside an
                    # item is not flattened into a sibling (measured while
                    # reviewing headings/lists/tables/code). Bounded so a
                    # pathological indent cannot eat the whole line.
                    depth = len(match[1].expandtabs(4)) // 2
                    indent = "  " + " " * (2 * min(depth, 8))
                    marker = "• " if match[2][0] in "-*+" else match[2]
                    prefix = indent + marker
                    if len(prefix) >= max(4, width // 2):
                        prefix = "  • "
                    body = _wrap(_inline(match[3], no_color), width - len(prefix))
                    output.append(prefix + body[0])
                    output.extend(" " * len(prefix) + extra for extra in body[1:])
                else:
                    output.extend(_wrap(_inline(segment, no_color), width))
        index += 1
    result = "\n".join(output)
    return SGR.sub("", result) if no_color else result
