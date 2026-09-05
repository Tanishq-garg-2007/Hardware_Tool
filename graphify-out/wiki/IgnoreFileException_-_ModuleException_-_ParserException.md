# IgnoreFileException / ModuleException / ParserException

> 42 nodes · cohesion 0.06

## Key Concepts

- **Magic** (13 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **ModuleException** (9 connections) — `Backend/binwalk/src/binwalk/core/exceptions.py`
- **ParserException** (9 connections) — `Backend/binwalk/src/binwalk/core/exceptions.py`
- **.parse()** (7 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **Signature** (7 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **.scan()** (6 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **SignatureLine** (6 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **IgnoreFileException** (5 connections) — `Backend/binwalk/src/binwalk/core/exceptions.py`
- **._analyze()** (5 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **._filtered()** (4 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **SignatureResult** (4 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **Exception** (3 connections)
- **._do_math()** (3 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **.__init__()** (3 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **.load()** (3 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **.match()** (3 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **object** (3 connections)
- **._generate_regex()** (3 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **.__init__()** (3 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **.__init__()** (3 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **.append()** (2 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **.__init__()** (2 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **Module exception class. Nothing special here except the name.** (1 connections) — `Backend/binwalk/src/binwalk/core/exceptions.py`
- **Special exception class used by the load_file plugin method to indicate that…** (1 connections) — `Backend/binwalk/src/binwalk/core/exceptions.py`
- **Exception thrown specifically for signature file parsing errors.** (1 connections) — `Backend/binwalk/src/binwalk/core/exceptions.py`
- *... and 17 more nodes in this community*

## Relationships

- [common / BlockFile() / critical()](common_-_BlockFile_-_critical.md) (9 shared connections)
- [bytes2str() / get_keys() / has_key()](bytes2str_-_get_keys_-_has_key.md) (2 shared connections)
- [get_class_name_from_method() / ExtractDetails / .__init__()](get_class_name_from_method_-_ExtractDetails_-_.__init__.md) (2 shared connections)
- [.callback() / Processes the result from all modules. Called for all dependency modules when a… / Plugin](callback_-_Processes_the_result_from_all_modules._Called_for_all_dependency_modules_when_a…_-_Plugin.md) (1 shared connections)
- [version / binwalk/__init__ / execute()](version_-_binwalk-__init___-_execute.md) (1 shared connections)
- [module / Kwarg / .__init__()](module_-_Kwarg_-_.__init__.md) (1 shared connections)

## Source Files

- `Backend/binwalk/src/binwalk/core/exceptions.py`
- `Backend/binwalk/src/binwalk/core/magic.py`

## Audit Trail

- EXTRACTED: 67 (94%)
- INFERRED: 4 (6%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*