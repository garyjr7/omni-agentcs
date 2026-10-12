"""Parsers that turn raw tool output into stable structured data.

``PARSERS_VERSION`` versions the parsing contract as a whole: it is stamped on
every tool result next to the tool's own ``contract_version`` (V1-8), so a
recorded run can be replayed against the parser revision that produced it
instead of whatever happens to be installed.
"""

PARSERS_VERSION = "1.0.0"

__all__ = ["PARSERS_VERSION"]
