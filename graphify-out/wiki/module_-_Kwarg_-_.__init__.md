# module / Kwarg / .__init__()

> 24 nodes · cohesion 0.17

## Key Concepts

- **module.py** (24 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **Option** (19 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **Kwarg** (18 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **modules/extractor.py** (17 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`
- **modules/__init__.py** (15 connections) — `Backend/binwalk/src/binwalk/modules/__init__.py`
- **general.py** (12 connections) — `Backend/binwalk/src/binwalk/modules/general.py`
- **compression.py** (11 connections) — `Backend/binwalk/src/binwalk/modules/compression.py`
- **disasm.py** (10 connections) — `Backend/binwalk/src/binwalk/modules/disasm.py`
- **modules/entropy.py** (10 connections) — `Backend/binwalk/src/binwalk/modules/entropy.py`
- **hexdiff.py** (8 connections) — `Backend/binwalk/src/binwalk/modules/hexdiff.py`
- **RawCompression** (7 connections) — `Backend/binwalk/src/binwalk/modules/compression.py`
- **signature.py** (7 connections) — `Backend/binwalk/src/binwalk/modules/signature.py`
- **show_help()** (5 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.__init__()** (2 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.__init__()** (2 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.convert()** (1 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **Convenience wrapper around binwalk.core.module.Modules.help. @fd - An object…** (1 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **A container class that allows modules to declare command line options.** (1 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **Class constructor. @kwargs - A dictionary of kwarg key-value pairs affected by…** (1 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **A container class allowing modules to specify their expected __init__ kwarg(s).** (1 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **Class constructor. @name - Kwarg name. @default - Default kwarg value.…** (1 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.run()** (1 connections) — `Backend/binwalk/src/binwalk/modules/compression.py`
- **# TODO: Add --dpoints option to set the number of data points?** (1 connections) — `Backend/binwalk/src/binwalk/modules/entropy.py`
- **# TODO: Should errors from all commands in a command string be checked?…** (1 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`

## Relationships

- [common / BlockFile() / critical()](common_-_BlockFile_-_critical.md) (22 shared connections)
- [Module / ._build_display_args() / .clear()](Module_-_._build_display_args_-_.clear.md) (9 shared connections)
- [bytes2str() / get_keys() / has_key()](bytes2str_-_get_keys_-_has_key.md) (9 shared connections)
- [Architecture / .__init__() / ArchResult](Architecture_-_.__init___-_ArchResult.md) (6 shared connections)
- [get_class_name_from_method() / ExtractDetails / .__init__()](get_class_name_from_method_-_ExtractDetails_-_.__init__.md) (6 shared connections)
- [Dependency / .__init__() / Error](Dependency_-_.__init___-_Error.md) (5 shared connections)
- [General / .file_name_filter() / .load()](General_-_.file_name_filter_-_.load.md) (5 shared connections)
- [HexDiff / ._color_filter() / ._colorize()](HexDiff_-_._color_filter_-_._colorize.md) (4 shared connections)
- [Called automatically by self.result. / Signature / .init()](Called_automatically_by_self.result._-_Signature_-_.init.md) (4 shared connections)
- [Deflate / .decompress() / .extractor()](Deflate_-_.decompress_-_.extractor.md) (4 shared connections)
- [file_md5() / file_size() / Creates a unique file name based on the specified base name. @base_name - The…](file_md5_-_file_size_-_Creates_a_unique_file_name_based_on_the_specified_base_name._@base_name_-_The….md) (3 shared connections)
- [version / binwalk/__init__ / execute()](version_-_binwalk-__init___-_execute.md) (1 shared connections)

## Source Files

- `Backend/binwalk/src/binwalk/core/module.py`
- `Backend/binwalk/src/binwalk/modules/__init__.py`
- `Backend/binwalk/src/binwalk/modules/compression.py`
- `Backend/binwalk/src/binwalk/modules/disasm.py`
- `Backend/binwalk/src/binwalk/modules/entropy.py`
- `Backend/binwalk/src/binwalk/modules/extractor.py`
- `Backend/binwalk/src/binwalk/modules/general.py`
- `Backend/binwalk/src/binwalk/modules/hexdiff.py`
- `Backend/binwalk/src/binwalk/modules/signature.py`

## Audit Trail

- EXTRACTED: 115 (89%)
- INFERRED: 14 (11%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*