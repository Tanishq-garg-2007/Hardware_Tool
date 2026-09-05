# .callback() / Processes the result from all modules. Called for all dependency modules when a… / Plugin

> 33 nodes · cohesion 0.08

## Key Concepts

- **Plugins** (17 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **Plugin** (9 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **._call_plugins()** (7 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.list_plugins()** (4 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.callback()** (3 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.__init__()** (3 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **._find_plugin_class()** (3 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **._load_plugin_modules()** (3 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.load_plugins()** (3 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.new_file()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.post_scan()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.pre_scan()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.scan()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.load_file_callbacks()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.new_file_callbacks()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.post_scan_callbacks()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.pre_scan_callbacks()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.scan_callbacks()** (2 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **object** (2 connections)
- **Processes the result from all modules. Called for all dependency modules when a…** (1 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.__str__()** (1 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.__enter__()** (1 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.__exit__()** (1 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **.__init__()** (1 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **Obtain a list of all user and system plugin modules. Returns a dictionary of: {…** (1 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- *... and 8 more nodes in this community*

## Relationships

- [common / BlockFile() / critical()](common_-_BlockFile_-_critical.md) (2 shared connections)
- [Module / ._build_display_args() / .clear()](Module_-_._build_display_args_-_.clear.md) (1 shared connections)
- [IgnoreFileException / ModuleException / ParserException](IgnoreFileException_-_ModuleException_-_ParserException.md) (1 shared connections)

## Source Files

- `Backend/binwalk/src/binwalk/core/module.py`
- `Backend/binwalk/src/binwalk/core/plugin.py`

## Audit Trail

- EXTRACTED: 43 (96%)
- INFERRED: 2 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*