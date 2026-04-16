from typing import Dict, Optional, Tuple

from agent_sec_cli.code_scanner.hook_adapter.utils.code_extractor import (
    extract_inline_code,
)
from agent_sec_cli.code_scanner.models import Language

# cosh tool_name -> (field in tool_input that holds the code, default language)
TOOL_EXTRACTORS: Dict[str, Tuple[str, Language]] = {
    "run_shell_command": ("command", Language.BASH),
}


def extract_code_and_language(
    tool_name: str,
    tool_input: dict,
) -> Tuple[Optional[str], Optional[Language]]:
    """Extract scannable code and its language from a cosh tool call.

    Steps:
      1. Look up *tool_name* in the extractor table to determine which field
         in *tool_input* carries the raw data and what the default language is.
      2. If the default language is BASH, try deep extraction via
         :func:`extract_inline_code` (e.g. ``python -c "..."`` nested in a
         shell command).  If successful, return the inner code and its language.
      3. Otherwise return the raw field value with its default language.

    Returns ``(None, None)`` when *tool_name* is not recognized or the
    relevant field is empty.
    """
    mapping = TOOL_EXTRACTORS.get(tool_name)
    if mapping is None:
        return (None, None)

    field, default_lang = mapping
    raw_code = tool_input.get(field)
    if not raw_code or not isinstance(raw_code, str) or not raw_code.strip():
        return (None, None)

    # For shell tools, try to detect inline code of another language
    if default_lang == Language.BASH:
        inline = extract_inline_code(raw_code)
        if inline is not None:
            return inline

    return (raw_code, default_lang)
