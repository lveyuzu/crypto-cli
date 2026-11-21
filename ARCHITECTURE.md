# Architecture

```
src/cryptix/
  errors.py            exception hierarchy -> exit codes
  core/
    data.py            bytes <-> text notations (hex, escapes, charsets); no lossy conversions
    textutil.py        shared ASCII/whitespace handling for text codecs
    plugin.py          PluginInfo, Param, role interfaces, structured results
    registry.py        registration, lookup, discovery (builtin / entry points / user files)
    magic.py           file-signature table
  plugins/             built-in operations; each module is auto-discovered
  cli/
    commands.py        ALL command logic: (Context, args) -> exit code
    context.py io.py   streams, options, input resolution, binary-safe output
    chain.py render.py chain-spec parser; tables (Rich only on a colour TTY)
    typer_app.py       primary frontend (thin binding)
    argparse_app.py    zero-dependency fallback frontend (thin binding)
    main.py            entry point
```

Principles: raw `bytes` everywhere; the CLI dispatcher knows nothing about individual operations (it asks the
registry); frontends contain no logic, so behaviour is tested once; stdout carries only the requested result;
every decoder maps all failures to `DecodeError` (fuzz-tested); search code (Milestone 2) will use only plugins
that declare `auto_safe`, ranked by `Decoder.detect()` confidence and bounded by cost class.
