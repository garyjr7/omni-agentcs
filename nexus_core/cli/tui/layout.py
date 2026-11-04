"""Four independent regions on the primary terminal screen."""

import asyncio
from typing import Any, Callable
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import StyleAndTextTuples
from prompt_toolkit.clipboard import ClipboardData
from prompt_toolkit.mouse_events import MouseEvent
from .paste import PasteRef

Snapshot = tuple[str, int, dict[int, PasteRef]]
from types import SimpleNamespace

from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.filters import Condition
from prompt_toolkit.layout import ConditionalContainer, Float, FloatContainer, HSplit, Layout, VSplit, Window, WindowAlign
from prompt_toolkit.layout import Margin, WindowRenderInfo
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.mouse_events import MouseEventType
from prompt_toolkit.layout.menus import MultiColumnCompletionsMenu
from prompt_toolkit.layout.processors import Processor, Transformation
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style


class RegionApplication(Application[Any]):
    """One adaptive refresh task: 4 Hz while busy, 0.5 Hz for the idle clock."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.refresh_wake = asyncio.Event()

    def _start_auto_refresh_task(self) -> None:
        async def refresh() -> None:
            while True:
                try:
                    await asyncio.wait_for(self.refresh_wake.wait(), self.refresh_interval or 2.0)
                    self.refresh_wake.clear()
                except asyncio.TimeoutError:
                    self.invalidate()
        self.create_background_task(refresh())


class ScrollbackControl(BufferControl):
    """Read-only transcript that turns a click on a card footer into a toggle.

    ``prompt_toolkit`` translates the absolute mouse coordinates to the content
    row before calling the control's ``mouse_handler``, so ``position.y`` is the
    logical transcript line. Only a left click on a registered toggle footer is
    consumed; every other event falls back to the buffer (selection/scroll).
    """

    def __init__(self, *args: Any, on_line_click: Callable[[int], bool] | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._on_line_click = on_line_click

    def mouse_handler(self, mouse_event: MouseEvent) -> Any:
        if (
            self._on_line_click is not None
            and mouse_event.event_type == MouseEventType.MOUSE_DOWN
            and self._on_line_click(int(mouse_event.position.y))
        ):
            return None
        return super().mouse_handler(mouse_event)


#: Hint drawn inside an empty editor. It is a rendering processor, never text:
#: it is not in the buffer, the history, the transcript or a submitted turn.
from .strings import HISTORY_HINT, HELP_HINT, PLACEHOLDER_TEXT

PLACEHOLDER = PLACEHOLDER_TEXT


class PlaceholderProcessor(Processor):
    """Grey hint for an empty, focused editor.

    ``prompt_toolkit`` 3 has no native placeholder for ``BufferControl``, so the
    hint is appended to the rendered row instead of being typed into the buffer.
    It disappears on the first character, on a paste chip (the document holds a
    reference, not literal text), on a secret prompt and while the permission
    menu is open, and it never changes the editor's height: one empty line stays
    one line.
    """

    def __init__(self, ui: Any, text: str = PLACEHOLDER) -> None:
        self._ui = ui
        self._text = text

    def visible(self) -> bool:
        """An empty, focused, non-secret editor with no modal on top."""
        ui = self._ui
        if ui._secret_mode or ui.approval_active:
            return False
        if ui._input.text or ui.input_document.refs:
            return False
        try:
            return ui._app.layout.current_control.buffer is ui._input
        except Exception:  # noqa: BLE001 - a frame must never fail to render
            return False

    def apply_transformation(self, ti: Any) -> Transformation:
        if not self.visible():
            return Transformation(ti.fragments)
        return Transformation([*ti.fragments, ("class:placeholder", self._text)])


def build_layout(ui: Any, keys: Any, history: Any, prompt_style: Any, input: Any, output: Any, full_screen: bool = False) -> None:
    from ..theme import THEME
    from .lexer import OmniLexer

    PANEL_STYLE = THEME.panel_style
    PANEL_BAR_STYLE = THEME.panel_bar_style

    class ConsoleInset(Margin):
        """Two blank cells that keep transcript and footer content off the edge."""

        def get_width(self, get_ui_content: Callable[[], Any]) -> int:
            del get_ui_content
            return 2

        def create_margin(self, window_render_info: WindowRenderInfo,
                          width: int, height: int) -> StyleAndTextTuples:
            del window_render_info
            return [("", " " * width + "\n") for _ in range(height)]

    inset = [ConsoleInset()]

    class ScrollbackLexer(Lexer):
        def lex_document(self, document: Document) -> Callable[[int], StyleAndTextTuples]:
            del document
            # Styles are parsed once when appended, never over the whole log
            # on each frame. The Buffer itself contains plain text, so a line
            # never changes identity: the working pulse is not one of them.
            def get_line(n: int) -> StyleAndTextTuples:
                return ui._styled_lines[n] if n < len(ui._styled_lines) else []
            return get_line

    ui._scrollback = Buffer(name="scrollback", read_only=True)
    class InputBuffer(Buffer):
        _segment_undo: list[Snapshot]
        _segment_redo: list[Snapshot]
        def reset(self, *args: Any, **kwargs: Any) -> None:
            self._segment_undo, self._segment_redo = [], []
            super().reset(*args, **kwargs)
            # Buffer.reset does not emit on_text_changed. Keep the typed side
            # document in sync before subsequent typeahead edits use its ranges.
            if getattr(ui, '_input', None) is self and not ui._secret_mode:
                ui.input_document.synchronize(self.text)

        def _edit_range(self, start: int, stop: int, replacement: str, cursor: int) -> bool:
            if self.read_only():
                from prompt_toolkit.buffer import EditReadOnlyBuffer
                raise EditReadOnlyBuffer()
            try:
                ui.input_document.replace_text(start, stop, replacement)
            except (ValueError, OSError) as exc:
                ui.print(f'Entrada conservada: {exc}')
                return False
            ui._set_input_document(cursor)
            return True

        def delete(self, count: int = 1) -> str:
            if ui._secret_mode:
                return super().delete(count)
            start = self.cursor_position
            stop = min(len(self.text), start+max(0, count))
            deleted = self.text[start:stop]
            return deleted if self._edit_range(start, stop, '', start) else ''

        def delete_before_cursor(self, count: int = 1) -> str:
            if ui._secret_mode:
                return super().delete_before_cursor(count)
            assert count >= 0
            stop = self.cursor_position
            start = max(0, stop-count)
            deleted = self.text[start:stop]
            return deleted if self._edit_range(start, stop, '', start) else ''

        def insert_text(self, data: str, overwrite: bool = False, move_cursor: bool = True, fire_event: bool = True) -> None:
            if ui._secret_mode:
                return super().insert_text(data, overwrite, move_cursor, fire_event)
            start = self.cursor_position
            overwritten = self.text[start:start+len(data)].split('\n', 1)[0] if overwrite else ''
            cursor = start+len(data) if move_cursor else start
            if self._edit_range(start, start+len(overwritten), data, cursor) and fire_event:
                self.on_text_insert.fire()
                from prompt_toolkit.application import get_app
                if self.completer and self.complete_while_typing():
                    get_app().create_background_task(self._async_completer())
                if self.auto_suggest:
                    get_app().create_background_task(self._async_suggester())

        def copy_selection(self, _cut: bool = False) -> ClipboardData:
            if ui._secret_mode:
                return super().copy_selection(_cut=_cut)
            from prompt_toolkit.clipboard import ClipboardData
            from prompt_toolkit.selection import SelectionType
            document = self.document
            ranges = list(document.selection_ranges()) if document.selection else []
            contents = [''.join(ui.input_document.refs[p].content if p in ui.input_document.refs
                                else self.text[p] for p in range(start, stop))
                        for start, stop in ranges]
            data = '\n'.join(contents)
            kind = document.selection.type if document.selection else SelectionType.CHARACTERS
            if kind == SelectionType.LINES and data.endswith('\n'):
                data = data[:-1]
            if _cut and ranges:
                from .paste import InputDocument
                edited = InputDocument()
                edited.text, edited.refs = self.text, dict(ui.input_document.refs)
                for start, stop in reversed(ranges):
                    edited.replace_text(start, stop, '')
                new_document, _ = document.cut_selection()
                if self.read_only():
                    from prompt_toolkit.buffer import EditReadOnlyBuffer
                    raise EditReadOnlyBuffer()
                try:
                    ui.input_document._commit(edited.text, edited.refs)
                except (ValueError, OSError) as exc:
                    ui.print(f'Entrada conservada: {exc}')
                    return ClipboardData('')
                ui._set_input_document(new_document.cursor_position)
            self.selection_state = None
            return ClipboardData(data, kind)

        def _snapshot(self) -> Snapshot:
            return self.text, self.cursor_position, dict(ui.input_document.refs)

        def save_to_undo_stack(self, clear_redo_stack: bool = True) -> None:
            if ui._secret_mode:
                return
            snapshot = self._snapshot()
            if self._segment_undo and self._segment_undo[-1][0] == self.text:
                self._segment_undo[-1] = snapshot
            else:
                self._segment_undo.append(snapshot)
                self._segment_undo = self._segment_undo[-32:]
            if clear_redo_stack:
                self._segment_redo = []

        def _restore(self, snapshot: Snapshot) -> None:
            text, cursor, refs = snapshot
            ui.input_document._commit(text, refs)
            ui._set_input_document(cursor)

        def undo(self) -> None:
            while self._segment_undo:
                snapshot = self._segment_undo.pop()
                if snapshot[0] != self.text or snapshot[2] != ui.input_document.refs:
                    self._segment_redo.append(self._snapshot())
                    self._restore(snapshot)
                    break

        def redo(self) -> None:
            if self._segment_redo:
                self.save_to_undo_stack(clear_redo_stack=False)
                self._restore(self._segment_redo.pop())

        def append_to_history(self) -> None:
            if not ui._secret_mode:
                text = ui.input_document.reconstruct()
                if text and (not self.history.get_strings() or self.history.get_strings()[-1] != text):
                    self.history.append_string(text)

    ui._input = InputBuffer(
        name="input", multiline=True, history=history,
        accept_handler=ui._accept, completer=ui._completer,
        complete_while_typing=ui._enable_completion, read_only=Condition(lambda: not ui._can_edit),
        enable_history_search=True, on_text_changed=ui._input_changed,
    )
    lexer = OmniLexer(no_color=ui.no_color)
    ui._scrollback_window = Window(
        ScrollbackControl(
            ui._scrollback, lexer=ScrollbackLexer(), focusable=False,
            on_line_click=ui.toggle_card_at_line,
        ),
        wrap_lines=True, always_hide_cursor=True, left_margins=inset,
    )
    # The working pulse and the "Worked for" summary are the same fixed row of
    # the dock, right above the input panel -never transcript lines, so they
    # cannot scroll away while the chat advances. They are mutually exclusive:
    # while the agent works the pulse has one row, when it stops the completion
    # line takes it.
    ui._busy_window = Window(FormattedTextControl(ui._render_busy),
                             height=lambda: int(ui._status.busy), left_margins=inset)
    ui._completion_window = Window(FormattedTextControl(ui._completion_formatted),
                                   height=lambda: int(bool(ui._completion_status)), left_margins=inset)
    ui._completion_gap = Window(height=lambda: int(bool(ui._completion_status)))
    # Transient prompt chips (trust/session/report, plus the paste keys hint).
    # They belong to the prompt, not to the textarea, so they render above the
    # panel: inside it the editor stays the top line and the footer the bottom.
    chips = Window(FormattedTextControl(lambda: ui._formatted(
        "\n".join(ui.prompt_text.splitlines()[:-1] + (["F3 expandir/editar pegado · F4 eliminar (cursor junto al chip)"] if ui.input_document.refs else [])))),
        height=lambda: max(0, len(ui.prompt_text.splitlines()) - 1) + bool(ui.input_document.refs),
        left_margins=inset)
    # While a secure prompt is active the input is masked through a conditional
    # ``PasswordProcessor``, so a secret is never rendered to the screen (see
    # ``TuiSession.prompt_secret``).
    from prompt_toolkit.layout.processors import ConditionalProcessor, PasswordProcessor

    ui._secret_mask = ConditionalProcessor(
        PasswordProcessor(char="•"), Condition(lambda: ui._secret_mode)
    )
    from .paste import PasteProcessor
    # Last in the chain: the hint is appended to an already-mapped empty row, so
    # the paste chip and the secret mask keep their own display mapping.
    ui._placeholder = PlaceholderProcessor(ui)
    editor = Window(BufferControl(
        ui._input, lexer=lexer,
        input_processors=[PasteProcessor(ui), ui._secret_mask, ui._placeholder],
    ), wrap_lines=True, style=PANEL_STYLE,
                    get_line_prefix=lambda line, wrapped: ui._formatted(
                        ui.prompt_text.splitlines()[-1] if line == 0 and wrapped == 0 else "  · "))
    # OpenCode-Zen style textarea: a dark grey panel whose only border is a solid
    # red vertical bar on the left. The editor is its top line and the agent's
    # identity (``model · cwd``) its bottom-left corner.
    outer_input_gap = Window(width=2, char=" ", style=PANEL_STYLE)
    bar = Window(width=1, char="│", style=PANEL_BAR_STYLE)
    footer = Window(FormattedTextControl(ui._workspace_footer), height=1,
                    align=WindowAlign.LEFT, style=PANEL_STYLE)
    top_padding = Window(height=1, style=PANEL_STYLE)
    input_padding = Window(height=1, style=PANEL_STYLE)
    bottom_padding = Window(height=1, style=PANEL_STYLE)
    input_gap = Window(width=1, char=" ", style=PANEL_STYLE)
    ui._bar_window = bar
    ui._footer_window = footer
    ui._chips_window = chips
    ui._editor_window = editor
    # The header owns its row from the first frame. A conditional height made
    # the banner start on row 0 and then be pushed down when the badge appeared
    # mid-session, so the header painted over the masthead instead of above it.
    badge = Window(FormattedTextControl(ui._header_badge), height=1,
                   align=WindowAlign.LEFT, style=THEME.badge_style, left_margins=inset)
    ui._badge_window = badge
    ui._input_window = VSplit(
        [outer_input_gap, bar, input_gap, HSplit([top_padding, editor, input_padding, footer, bottom_padding],
                                height=ui._input_height)],
        height=ui._input_height,
    )
    # The helper hints are a static footer line outside the panel, and the
    # operational bar only occupies a row when it has an alert to show.
    hints = Window(FormattedTextControl(f"← {HISTORY_HINT} · ? {HELP_HINT}"), height=1,
                   style=THEME.hints_style, left_margins=inset)
    hints_top_margin = Window(height=1)
    hints_bottom_margin = Window(height=1)
    ui._hints_top_margin = hints_top_margin
    ui._hints_bottom_margin = hints_bottom_margin
    ui._hints_window = hints
    ui._status_window = Window(FormattedTextControl(ui._toolbar),
                               height=lambda: int(bool(ui._toolbar())), left_margins=inset)
    ui._regions = [ui._scrollback_window, ui._input_window]
    # The engagement plan is an overlay Float; it does not consume space in
    # the transcript or prompt dock.
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
    # The permission request grows out of the input panel instead of floating
    # over the transcript: it is zero rows while idle, and while a HIGH/
    # DESTRUCTIVE call waits for the operator the prompt docks upward, showing
    # the question, the arguments and the three options inside the same panel
    # (same red left bar, dark background).
    def approval_height() -> int:
        if not ui.approval_active:
            return 0
        # The menu shares the dock with the input panel, so on a short terminal
        # it yields rows instead of pushing the editor off the screen.
        try:
            rows = int(ui._session.output.get_size().rows)
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            rows = 24
        return min(12, max(4, len(ui._approval_lines())), max(4, rows - 8))

    ui._approval_window = Window(
        FormattedTextControl(ui._approval_formatted), wrap_lines=True,
        height=approval_height, style=THEME.approval_surface_style,
    )
    ui._approval_bar = Window(width=1, char="│", style=PANEL_BAR_STYLE)
    ui._approval_panel = VSplit(
        [outer_input_gap, ui._approval_bar, input_gap, ui._approval_window],
        height=approval_height,
    )
    # Keep the prompt dock fixed, with the transcript as the only execution
    # output surface. The completion line and the permission menu are rows of
    # the dock itself: never overlays, never a fifth region.
    ui._thought_row = ConditionalContainer(
        Window(
            FormattedTextControl(ui._thought_formatted), wrap_lines=True,
            height=ui.thought_height,
        ),
        filter=Condition(lambda: bool(ui.thought_active and not ui.answer_active)),
    )
    ui._rows = [badge, ui._scrollback_window, chips, ui._thought_row,
                ui._busy_window, ui._completion_window, ui._approval_panel,
                ui._input_window, hints_top_margin, hints, hints_bottom_margin]
    # The streaming answer is a live overlay above the input bar: it re-renders
    # the markdown of the growing answer and is committed to the scrollback when
    # the stream ends. Like the panel and the modal, it is not a fifth region.
    ui._answer_window = Window(
        FormattedTextControl(ui._answer_formatted), wrap_lines=True,
        height=lambda: max(1, ui.answer_height()),
    )
    ui._answer_float = Float(
        content=ConditionalContainer(
            ui._answer_window, filter=Condition(lambda: bool(ui.answer_active))
        ),
        bottom=3, left=2, right=2,
    )
    # Live ReAct "thinking": one to three wrapped lines above the input bar,
    # showing the model's reasoning as it streams. Not a fifth region. The
    # ``_thought_float`` below stays built but unmounted: its contract is
    # asserted by test_tui_accordion and the live surface is ``_thought_row``.
    ui._thought_window = Window(
        FormattedTextControl(ui._thought_formatted), wrap_lines=True, height=2,
    )
    ui._thought_float = Float(
        content=ConditionalContainer(
            ui._thought_window,
            filter=Condition(lambda: bool(ui.thought_active and not ui.answer_active))
        ),
        bottom=3, left=2, right=2,
    )
    ui._tasks_float = Float(
        content=ConditionalContainer(
            Window(FormattedTextControl(lambda: ui.task_panel.render(no_color=ui.no_color)),
                   height=lambda: len(ui.task_panel.render()), wrap_lines=False),
            filter=Condition(lambda: bool(ui.task_panel.tasks))),
        bottom=6, left=2, right=2,
    )
    # Reserve its own row, so the badge never obscures transcript content.
    root = FloatContainer(HSplit(ui._rows), [
        Float(xcursor=True, ycursor=True, content=MultiColumnCompletionsMenu(show_meta=True)),
        ui._panel_float,
    ])
    ui._app = RegionApplication(
        layout=Layout(root, focused_element=editor), full_screen=bool(full_screen),
        # Mouse capture is required for the wheel to scroll the transcript in
        # alt-screen; text selection then needs Shift (terminal-level).
        mouse_support=True, refresh_interval=None, min_redraw_interval=0.25,
        key_bindings=keys, input=input, output=output,
        style=Style.from_dict({
            **panel_style(), **approval_style(), **THEME.prompt_toolkit_styles(),
            **(prompt_style or {}),
        }),
        color_depth=ColorDepth.DEPTH_1_BIT if ui.no_color else ColorDepth.DEPTH_24_BIT,
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
