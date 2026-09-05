# bytes2str() / get_keys() / has_key()

> 53 nodes · cohesion 0.05

## Key Concepts

- **Modules** (22 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **Entropy** (13 connections) — `Backend/binwalk/src/binwalk/modules/entropy.py`
- **iterator()** (12 connections) — `Backend/binwalk/src/binwalk/core/compat.py`
- **has_key()** (10 connections) — `Backend/binwalk/src/binwalk/core/compat.py`
- **.argv()** (7 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **._set_arguments()** (7 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.run()** (6 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **Status** (6 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **bytes2str()** (5 connections) — `Backend/binwalk/src/binwalk/core/compat.py`
- **.execute()** (5 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.kwargs()** (5 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.load()** (5 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.dependencies()** (4 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.__init__()** (4 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **process_kwargs()** (4 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **get_keys()** (3 connections) — `Backend/binwalk/src/binwalk/core/compat.py`
- **.list()** (3 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.clear()** (3 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- **.calculate_file_entropy()** (3 connections) — `Backend/binwalk/src/binwalk/modules/entropy.py`
- **.gzip()** (3 connections) — `Backend/binwalk/src/binwalk/modules/entropy.py`
- **.init()** (3 connections) — `Backend/binwalk/src/binwalk/modules/entropy.py`
- **.plot_entropy()** (3 connections) — `Backend/binwalk/src/binwalk/modules/entropy.py`
- **.shannon_numpy()** (3 connections) — `Backend/binwalk/src/binwalk/modules/entropy.py`
- **.edit_rules()** (3 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`
- **.cleanup()** (2 connections) — `Backend/binwalk/src/binwalk/core/module.py`
- *... and 28 more nodes in this community*

## Relationships

- [module / Kwarg / .__init__()](module_-_Kwarg_-_.__init__.md) (9 shared connections)
- [Module / ._build_display_args() / .clear()](Module_-_._build_display_args_-_.clear.md) (5 shared connections)
- [common / BlockFile() / critical()](common_-_BlockFile_-_critical.md) (4 shared connections)
- [get_class_name_from_method() / ExtractDetails / .__init__()](get_class_name_from_method_-_ExtractDetails_-_.__init__.md) (3 shared connections)
- [Dependency / .__init__() / Error](Dependency_-_.__init___-_Error.md) (3 shared connections)
- [Display / .add_custom_header() / ._append_to_data_parts()](Display_-_.add_custom_header_-_._append_to_data_parts.md) (2 shared connections)
- [file_md5() / file_size() / Creates a unique file name based on the specified base name. @base_name - The…](file_md5_-_file_size_-_Creates_a_unique_file_name_based_on_the_specified_base_name._@base_name_-_The….md) (2 shared connections)
- [version / binwalk/__init__ / execute()](version_-_binwalk-__init___-_execute.md) (2 shared connections)
- [IgnoreFileException / ModuleException / ParserException](IgnoreFileException_-_ModuleException_-_ParserException.md) (2 shared connections)
- [GenericContainer / .__init__() / MathExpression](GenericContainer_-_.__init___-_MathExpression.md) (1 shared connections)
- [HexDiff / ._color_filter() / ._colorize()](HexDiff_-_._color_filter_-_._colorize.md) (1 shared connections)

## Source Files

- `Backend/binwalk/src/binwalk/core/compat.py`
- `Backend/binwalk/src/binwalk/core/module.py`
- `Backend/binwalk/src/binwalk/modules/entropy.py`
- `Backend/binwalk/src/binwalk/modules/extractor.py`

## Audit Trail

- EXTRACTED: 103 (96%)
- INFERRED: 4 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*