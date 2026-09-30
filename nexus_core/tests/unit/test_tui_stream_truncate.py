from pathlib import Path

from nexus_core.cli.tui.stream import truncate_output, output_text

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_truncate_one_line():
    assert truncate_output("hello") == ("hello", False)


def test_truncate_three_lines_no_marker():
    assert truncate_output("a\nb\nc") == ("a\nb\nc", False)


def test_truncate_ten_lines_shows_head_tail():
    assert truncate_output("\n".join(map(str, range(10)))) == ("0\n...\n8\n9", True)


def test_truncate_skips_empty_lines():
    assert truncate_output("\na\n\n\nb\n") == ("a\nb", False)


def test_truncate_preserves_indentation():
    assert truncate_output("  a\n    b") == ("  a\n    b", False)


def test_truncate_empty_output():
    assert truncate_output("") == ("", False)


def test_truncate_whitespace_only():
    assert truncate_output(" \n\t") == ("", False)


def test_truncate_long_single_line_truncated_by_width():
    text, cut = truncate_output("a" * 200)
    assert cut and len(text) == 100 and text.endswith("…")


def test_truncate_nmap_real_fixture():
    from nexus_core.tools.parsers.nmap import parse_nmap_xml
    scan = parse_nmap_xml((FIXTURES / "nmap/scan_single_host.xml").read_text()).to_dict()
    text, cut = truncate_output(output_text({"output": {"scan": scan}}))
    assert text.startswith("Host up:") and "Nmap done" in text
    assert cut and "..." in text


def test_truncate_nuclei_real_fixture():
    source = (FIXTURES / "nuclei/findings.jsonl").read_text()
    text, _ = truncate_output(source)
    assert text.splitlines()[0] == truncate_output(source.splitlines()[0])[0]
    assert len([line for line in text.splitlines() if line != "..."]) <= 3


def test_truncate_filters_separators_and_duplicate_progress():
    assert truncate_output("---\n[+] wait\n[+] wait\nresult") == ("[+] wait\nresult", False)
