# Third-party material in the AD audit core

The files of `newton_mcp/ad/` are MIT, like the rest of Newton.  Two of
them carry material adapted from ActiveDirectoryMCP, and the notice of
that project is at the top of each of them:

```
Portions adapted from ActiveDirectoryMCP, Copyright (c) 2024 Alperen Adalar, MIT License
```

- `forbidden.py` — the forbidden-attribute list.  The list of SPEC-1.3
  section 4 is normative for Newton and is a superset of ActiveDirectoryMCP's
  `SENSITIVE_FILTER_ATTRIBUTES`, with the four deltas the spec names.  The
  case-insensitive comparison and the stripping of the `;binary` and
  `;range=` options follow the same idea.
- `queryset.py` — the filter tokenizer and the attribute-name rules.  The
  idea of a filter-fragment policy (balanced parentheses, no extensible
  match, a sensitive-attribute deny list) comes from
  `active_directory_mcp/validation.py`; the tokenizer itself is Newton's
  own and small, because Newton has no `ldap3` dependency (SPEC-1.3
  section 3).

Nothing else of ActiveDirectoryMCP is used, and no file of that project
was copied whole.

## ActiveDirectoryMCP

Source: <https://github.com/alpadalar/ActiveDirectoryMCP> (v5.0.0, as
consulted in a local checkout of ActiveDirectoryMCP).

MIT License

Copyright (c) 2024 Alperen Adalar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
