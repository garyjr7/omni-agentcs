"""Four independent regions on the primary terminal screen."""

import asyncio
from types import SimpleNamespace

from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.filters import Condition
from prompt_toolkit.layout import ConditionalContainer, Float, FloatContainer, HSplit, Layout, Window
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.layout.menus import MultiColumnCompletionsMenu
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style


class RegionApplication(Application):
    """One adaptive refresh task: 4 Hz while busy, 0.5 Hz for the idle clock."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.refresh_wake = asyncio.Event()

    def _start_auto_refresh_task(self):
        async def refresh():
            while True:
                try:
                    await asyncio.wait_for(self.refresh_wake.wait(), self.refresh_interval or 2.0)
                    self.refresh_wake.clear()
                except asyncio.TimeoutError:
                    self.invalidate()
        self.create_background_task(refresh())


def build_layout(ui, keys, history, prompt_style, input, output, full_screen=False):
    from .lexer import OmniLexer

    class ScrollbackLexer(Lexer):
        def lex_document(self, document):
            # Styles are parsed once when appended, never over the whole log
            # on each frame. The Buffer itself contains plain text.
            return lambda n: ui._styled_lines[n] if n < len(ui._styled_lines) else []

    ui._scrollback = Buffer(name="scrollback", read_only=True)
    ui._input = Buffer(
        name="input", multiline=True, history=history,
        accept_handler=ui._accept, completer=ui._completer,
        complete_while_typing=True, read_only=Condition(lambda: not ui._can_edit),
        enable_history_search=True,
    )
    lexer = OmniLexer(no_color=ui.no_color)
    ui._scrollback_window = Window(
        BufferControl(ui._scrollback, lexer=ScrollbackLexer(), focusable=False),
        wrap_lines=True, always_hide_cursor=True,
    )
    ui._busy_window = Window(FormattedTextControl(ui._render_busy),
                             height=lambda: int(ui._status.busy))
    header = Window(FormattedTextControl(lambda: ui._formatted(
        "\n".join(ui.prompt_text.splitlines()[:-1]))),
        height=lambda: max(0, len(ui.prompt_text.splitlines()) - 1))
    editor = Window(BufferControl(ui._input, lexer=lexer), wrap_lines=True,
                    get_line_prefix=lambda line, wrapped: ui._formatted(
                        ui.prompt_text.splitlines()[-1] if line == 0 and wrapped == 0 else "  · "))
    ui._input_window = HSplit([header, editor], height=ui._input_height)
    ui._status_window = Window(FormattedTextControl(ui._toolbar),
                               height=lambda: int(ui.status_bar_enabled))
    ui._regions = [ui._scrollback_window, ui._busy_window, ui._input_window, ui._status_window]
    # The engagement plan is an overlay Float, not a fifth region: the
    # four-region invariant of the inline layout stays intact.
    from .panels import approval_style, panel_style

    ui._panel_window = Window(
        FormattedTextControl(ui._panel_formatted), width=D(46), wrap_lines=True,
        height=lambda: min(24, max(3, len(ui._panel_formatted()))),
    )
    ui._panel_float = Float(
        content=ConditionalContainer(
            ui._panel_window, filter=Condition(lambda: bool(ui.panel_enabled))
        ),
        top=1, right=0, width=46,
    )
    # The approval request is a modal Float: it only appears while a HIGH/
    # DESTRUCTIVE tool waits for the operator and never becomes a fifth region.
    ui._approval_window = Window(
        FormattedTextControl(ui._approval_formatted), width=D(64), wrap_lines=True,
        height=lambda: min(20, max(3, len(ui._approval_formatted()))),
    )
    ui._approval_float = Float(
        content=ConditionalContainer(
            ui._approval_window, filter=Condition(lambda: bool(ui.approval_active))
        ),
        top=2, right=2, width=64,
    )
    root = FloatContainer(HSplit(ui._regions), [
        Float(xcursor=True, ycursor=True, content=MultiColumnCompletionsMenu(show_meta=True)),
        ui._panel_float,
        ui._approval_float,
    ])
    ui._app = RegionApplication(
        layout=Layout(root, focused_element=editor), full_screen=bool(full_screen),
        mouse_support=False, refresh_interval=None, min_redraw_interval=0.25,
        key_bindings=keys, input=input, output=output,
        style=Style.from_dict({
            **panel_style(), **approval_style(), "busy": "ansiyellow", **(prompt_style or {}),
        }),
        color_depth=ColorDepth.DEPTH_1_BIT if ui.no_color else None,
    )
    ui._app.ttimeoutlen = 0.1
    ui._app.timeoutlen = 0.3
    # Preserve the existing facade used by CLI renderers and embedded clients.
    ui._session = SimpleNamespace(
        app=ui._app, output=ui._app.output, default_buffer=ui._input,
        lexer=lexer, completer=ui._completer,
        bottom_toolbar=ui._toolbar if ui.status_bar_enabled else None,
        prompt_continuation=lambda *args: "  · ",
    )
