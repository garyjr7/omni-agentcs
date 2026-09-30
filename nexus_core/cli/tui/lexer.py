"""Small input lexer; tokenization never changes what the operator submits."""

import re

from prompt_toolkit.lexers import Lexer

TOKEN = re.compile(
    r'''(?P<string>"[^"\n]*"?|'[^'\n]*'?)'''
    r"|(?P<tool>\bnexus\.[\w.]+)"
    r"|(?P<key>\b[\w]+=(?=\S|$))"
    r"|(?P<path>(?:\./|\.\./|~/|/)[^\s\"']*)"
)


class OmniLexer(Lexer):
    def __init__(self, *, no_color=False):
        self.no_color = no_color

    def lex_document(self, document):
        def get_line(lineno):
            if lineno >= len(document.lines):
                return []
            line = document.lines[lineno]
            if self.no_color:
                return [("", line)]
            fragments = []
            position = 0
            for match in TOKEN.finditer(line):
                fragments.append(("", line[position:match.start()]))
                kind = match.lastgroup
                value = match.group()
                if kind == "path" and match.start() == 0 and re.fullmatch(r"/[\w-]+", value):
                    style = "ansicyan bold"
                else:
                    style = {"tool": "ansimagenta", "key": "ansiyellow",
                             "string": "ansigreen", "path": "ansicyan underline"}[kind]
                fragments.append((style, value))
                position = match.end()
            fragments.append(("", line[position:]))
            return fragments
        return get_line
