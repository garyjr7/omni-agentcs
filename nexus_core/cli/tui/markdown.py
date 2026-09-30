"""Dependency-free terminal rendering of the common Markdown subset."""

import re
import textwrap

SGR = re.compile(r"\x1b\[[0-9;]*m")
INLINE = re.compile(r"(`[^`]+`|\*\*.+?\*\*|__.+?__|(?<!\*)\*[^*]+\*(?!\*)|\[[^\]]+\]\([^)]+\))")


def _style(text, code, no_color):
    return text if no_color else f"\x1b[{code}m{text}\x1b[0m"


def _inline(text, no_color):
    def replace(match):
        value = match.group()
        if value.startswith("`"):
            return _style(value[1:-1], "100", no_color)
        if value.startswith(("**", "__")):
            return _style(value[2:-2], "1", no_color)
        if value.startswith("*"):
            return _style(value[1:-1], "3", no_color)
        label, url = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", value).groups()
        return f"{label} ({url})"
    return INLINE.sub(replace, text)


def _table(rows, width, no_color):
    cells = [[_inline(cell.strip(), True) for cell in row.strip().strip("|").split("|")] for row in rows]
    cells = [row for row in cells if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in row)]
    columns = max(map(len, cells))
    sizes = [max(1, max(len(row[i]) if i < len(row) else 0 for row in cells)) for i in range(columns)]
    budget = max(columns, width - 3 * columns - 1)
    while sum(sizes) > budget and max(sizes) > 1:
        index = sizes.index(max(sizes))
        sizes[index] -= 1
    border = "+" + "+".join("-" * (size + 2) for size in sizes) + "+"
    result = [border]
    for index, row in enumerate(cells):
        wrapped = [textwrap.wrap(row[i] if i < len(row) else "", size) or [""] for i, size in enumerate(sizes)]
        for n in range(max(map(len, wrapped))):
            result.append("| " + " | ".join((lines[n] if n < len(lines) else "").ljust(size)
                                           for lines, size in zip(wrapped, sizes)) + " |")
        if index == 0:
            result.append(border)
    result.append(border)
    return "\n".join(result)


def render_markdown(text: str, *, no_color=False, max_width=None) -> str:
    """Render headings, emphasis, links, lists, fences and pipe tables.

    Preserve literal code (including Markdown punctuation). No HTML, images,
    remote resources, terminal hyperlinks, subprocesses or optional imports.
    """
    width = max(20, int(max_width or 88))
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
            output.append(_table(rows, width, no_color))
            continue
        elif match := re.match(r"^(#{1,6})\s+(.+)$", line):
            output.append(_style(_inline(match[2], no_color), "1;4" if len(match[1]) == 1 else "1", no_color))
        elif match := re.match(r"^\s*([-*+] |\d+[.)] )(.+)$", line):
            prefix = "  • " if match[1][0] in "-*+" else "  " + match[1]
            output.append(prefix + _inline(match[2], no_color))
        else:
            output.append(_inline(line, no_color))
        index += 1
    result = "\n".join(output)
    return SGR.sub("", result) if no_color else result
