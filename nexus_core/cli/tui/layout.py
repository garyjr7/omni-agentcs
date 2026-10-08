"""Four independent regions on the primary terminal screen."""

import asyncio
from types import SimpleNamespace

from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.filters import Condition
from prompt_toolkit.layout import ConditionalContainer, Float, FloatContainer, HSplit, Layout, Window
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.mouse_events import MouseEventType
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


class ScrollbackControl(BufferControl):
    """Read-only transcript that turns a click on a card footer into a toggle.

    ``prompt_toolkit`` translates the absolute mouse coordinates to the content
    row before calling the control's ``mouse_handler``, so ``position.y`` is the
    logical transcript line. Only a left click on a registered toggle footer is
    consumed; every other event falls back to the buffer (selection/scroll).
    """

    def __init__(self, *args, on_line_click=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._on_line_click = on_line_click

    def mouse_handler(self, mouse_event):
        if (
            self._on_line_click is not None
            and mouse_event.event_type == MouseEventType.MOUSE_DOWN
            and self._on_line_click(int(mouse_event.position.y))
        ):
            return None
        return super().mouse_handler(mouse_event)


def build_layout(ui, keys, history, prompt_style, input, output, full_screen=False):
    from .lexer import OmniLexer

    class ScrollbackLexer(Lexer):
        def lex_document(self, document):
            # Styles are parsed once when appended, never over the whole log
            # on each frame. The Buffer itself contains plain text.
            return lambda n: ui._styled_lines[n] if n < len(ui._styled_lines) else []

    ui._scrollback = Buffer(name="scrollback", read_only=True)
    class InputBuffer(Buffer):
        def reset(self, *args, **kwargs):
            self._segment_undo, self._segment_redo = [], []
            result = super().reset(*args, **kwargs)
            # Buffer.reset does not emit on_text_changed. Keep the typed side
            # document in sync before subsequent typeahead edits use its ranges.
            if getattr(ui, '_input', None) is self and not ui._secret_mode:
                ui.input_document.synchronize(self.text)
            return result

        def _edit_range(self, start, stop, replacement, cursor):
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

        def delete(self, count=1):
            if ui._secret_mode:
                return super().delete(count)
            start = self.cursor_position
            stop = min(len(self.text), start+max(0, count))
            deleted = self.text[start:stop]
            return deleted if self._edit_range(start, stop, '', start) else ''

        def delete_before_cursor(self, count=1):
            if ui._secret_mode:
                return super().delete_before_cursor(count)
            assert count >= 0
            stop = self.cursor_position
            start = max(0, stop-count)
            deleted = self.text[start:stop]
            return deleted if self._edit_range(start, stop, '', start) else ''

        def insert_text(self, data, overwrite=False, move_cursor=True, fire_event=True):
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

        def copy_selection(self, _cut=False):
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

        def _snapshot(self):
            return self.text, self.cursor_position, dict(ui.input_document.refs)

        def save_to_undo_stack(self, clear_redo_stack=True):
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

        def _restore(self, snapshot):
            text, cursor, refs = snapshot
            ui.input_document._commit(text, refs)
            ui._set_input_document(cursor)

        def undo(self):
            while self._segment_undo:
                snapshot = self._segment_undo.pop()
                if snapshot[0] != self.text or snapshot[2] != ui.input_document.refs:
                    self._segment_redo.append(self._snapshot())
                    self._restore(snapshot)
                    break

        def redo(self):
            if self._segment_redo:
                self.save_to_undo_stack(clear_redo_stack=False)
                self._restore(self._segment_redo.pop())

        def append_to_history(self):
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
        wrap_lines=True, always_hide_cursor=True,
    )
    ui._busy_window = Window(FormattedTextControl(ui._render_busy),
                             height=lambda: int(ui._status.busy))
    header = Window(FormattedTextControl(lambda: ui._formatted(
        "\n".join(ui.prompt_text.splitlines()[:-1] + (["F3 expandir/editar pegado · F4 eliminar (cursor junto al chip)"] if ui.input_document.refs else [])))),
        height=lambda: max(0, len(ui.prompt_text.splitlines()) - 1) + bool(ui.input_document.refs))
    # While a secure prompt is active the input is masked through a conditional
    # ``PasswordProcessor``, so a secret is never rendered to the screen (see
    # ``TuiSession.prompt_secret``).
    from prompt_toolkit.layout.processors import ConditionalProcessor, PasswordProcessor

    ui._secret_mask = ConditionalProcessor(
        PasswordProcessor(char="•"), Condition(lambda: ui._secret_mode)
    )
    from .paste import PasteProcessor
    editor = Window(BufferControl(
        ui._input, lexer=lexer, input_processors=[PasteProcessor(ui), ui._secret_mask]
    ), wrap_lines=True,
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
        bottom=3, left=1, right=1,
    )
    # Live ReAct "thinking": one or two wrapped lines above the input bar,
    # showing the model's reasoning as it streams. Not a fifth region.
    ui._thought_window = Window(
        FormattedTextControl(ui._thought_formatted), wrap_lines=True, height=2,
    )
    ui._thought_float = Float(
        content=ConditionalContainer(
            ui._thought_window, filter=Condition(lambda: bool(ui.thought_active))
        ),
        bottom=3, left=1, right=1,
    )
    ui._tasks_float = Float(
        content=ConditionalContainer(
            Window(FormattedTextControl(lambda: ui.task_panel.render(no_color=ui.no_color)),
                   height=lambda: len(ui.task_panel.render()), wrap_lines=False),
            filter=Condition(lambda: bool(ui.task_panel.tasks))),
        bottom=6, left=0, right=0,
    )
    root = FloatContainer(HSplit(ui._regions), [
        ui._tasks_float,
        Float(xcursor=True, ycursor=True, content=MultiColumnCompletionsMenu(show_meta=True)),
        ui._panel_float,
        ui._approval_float,
        ui._answer_float,
        ui._thought_float,
    ])
    ui._app = RegionApplication(
        layout=Layout(root, focused_element=editor), full_screen=bool(full_screen),
        # Mouse capture is required for the wheel to scroll the transcript in
        # alt-screen; text selection then needs Shift (terminal-level).
        mouse_support=True, refresh_interval=None, min_redraw_interval=0.25,
        key_bindings=keys, input=input, output=output,
        style=Style.from_dict({
            **panel_style(), **approval_style(), "busy": "#00e5ff",
            "scroll": "#00e5ff", **(prompt_style or {}),
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
