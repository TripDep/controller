"""Q161-Q166/Q169: source-byte FiveM map resource declaration semantics.

The exact fxmanifest.lua bytes must already have been independently reopened
from the current Controller attempt and matched to the pre-D SHA pin by the
caller. A string containing a .ytyp path is NOT an active data_file directive.
This is a static resource preflight, not proof of FiveM execution or MG0.
"""
import re

MAX_BYTES = 200_000
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PATH = re.compile(r"[A-Za-z0-9_./-]+")
DIRECTIVES = frozenset(("fx_version", "game", "this_is_a_map",
                        "files", "data_file"))


def lex(raw):
    """Tokenize a restricted Lua source without executing it.

    Comments and quoted strings are distinct token types. Unterminated strings
    or block comments fail closed, rather than letting commented declarations
    count as executable fxmanifest entries.
    """
    if type(raw) is not bytes or not raw or len(raw) > MAX_BYTES:
        return None
    try:
        src = raw.decode("utf-8")
    except UnicodeError:
        return None
    out = []
    i = 0
    while i < len(src):
        ch = src[i]
        if ch.isspace():
            i += 1
            continue
        if src.startswith("--[[", i):
            end = src.find("]]", i+4)
            if end < 0:
                return None
            i = end+2
            continue
        if src.startswith("--", i):
            end = src.find("\n", i+2)
            i = len(src) if end < 0 else end+1
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            value = []
            while i < len(src) and src[i] != quote:
                if src[i] == "\\":
                    i += 1
                    if i >= len(src):
                        return None
                    escaped = {"n":"\n", "r":"\r", "t":"\t",
                               "\\":"\\", "'":"'", '"':'"'}
                    if src[i] not in escaped:
                        return None
                    value.append(escaped[src[i]])
                else:
                    value.append(src[i])
                i += 1
            if i >= len(src):
                return None
            out.append(("str", "".join(value)))
            i += 1
            continue
        match = IDENT.match(src, i)
        if match:
            out.append(("id", match.group()))
            i = match.end()
            continue
        if ch in "{}(),=[]":
            out.append(("punct", ch))
            i += 1
            continue
        # Operators and arbitrary Lua code are not accepted as manifest proof.
        out.append(("other", ch))
        i += 1
    return out


def safe_ytyp(path):
    return (type(path) is str and bool(PATH.fullmatch(path))
            and path.startswith("stream/") and path.endswith(".ytyp")
            and len(path) <= 240 and "\\" not in path
            and all(part not in ("", ".", "..") for part in path.split("/")))


def parse(raw):
    """Return a verified *static* source declaration, never a runtime verdict.

    Every .ytyp in files{} must have an actual DLC_ITYP_REQUEST data_file
    declaration and vice versa. A comment, print string, duplicate, traversal
    path or malformed Lua literal cannot masquerade as an active declaration.
    """
    tokens = lex(raw)
    if tokens is None:
        return {"valid":False, "ytyp_paths":(), "reason":"INVALID_SOURCE"}
    found = {}
    file_paths = []
    data_paths = []
    i = 0
    depth = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind == "punct" and value in "({[":
            depth += 1
            i += 1
            continue
        if kind == "punct" and value in ")}]":
            depth -= 1
            if depth < 0:
                return {"valid":False, "ytyp_paths":(), "reason":"UNBALANCED_LUA"}
            i += 1
            continue
        if depth or kind != "id" or value not in DIRECTIVES:
            i += 1
            continue
        if value in ("fx_version", "game", "this_is_a_map"):
            if value in found or i+1 >= len(tokens) or tokens[i+1][0] != "str":
                return {"valid":False, "ytyp_paths":(), "reason":"DIRECTIVE_SCHEMA"}
            found[value] = tokens[i+1][1]
            i += 2
            continue
        if value == "data_file":
            if (i+2 >= len(tokens) or tokens[i+1][0] != "str"
                    or tokens[i+2][0] != "str"):
                return {"valid":False, "ytyp_paths":(), "reason":"DATA_FILE_SCHEMA"}
            typ, path = tokens[i+1][1], tokens[i+2][1]
            if typ == "DLC_ITYP_REQUEST":
                data_paths.append(path)
            i += 3
            continue
        if value == "files":
            if "files" in found or i+1 >= len(tokens) or tokens[i+1] != ("punct", "{"):
                return {"valid":False, "ytyp_paths":(), "reason":"FILES_SCHEMA"}
            found["files"] = True
            i += 2
            expect_string = True
            while i < len(tokens) and tokens[i] != ("punct", "}"):
                kind, entry = tokens[i]
                if expect_string and kind == "str":
                    file_paths.append(entry)
                    expect_string = False
                elif not expect_string and (kind, entry) == ("punct", ","):
                    expect_string = True
                else:
                    return {"valid":False, "ytyp_paths":(), "reason":"FILES_ENTRIES"}
                i += 1
            if i >= len(tokens):
                return {"valid":False, "ytyp_paths":(), "reason":"FILES_UNCLOSED"}
            i += 1
            continue
    paths = [x for x in file_paths if x.endswith(".ytyp")]
    valid = bool(
        depth == 0 and found.get("fx_version") in ("cerulean", "adamant", "bodacious")
        and found.get("game") == "gta5"
        and found.get("this_is_a_map") == "yes"
        and found.get("files") is True and paths and data_paths
        and all(safe_ytyp(x) for x in paths + data_paths)
        and len(paths) == len(set(paths))
        and len(data_paths) == len(set(data_paths))
        and set(paths) == set(data_paths)
    )
    return {"valid":valid,
            "ytyp_paths":tuple(sorted(paths)) if valid else (),
            "reason":"VALID_STATIC_RESOURCE" if valid else "MISSING_OR_MISMATCHED_ITYP"}
