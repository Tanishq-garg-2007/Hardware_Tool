# common / BlockFile() / critical()

> 40 nodes · cohesion 0.08

## Key Concepts

- **common.py** (38 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **compat.py** (27 connections) — `Backend/binwalk/src/binwalk/core/compat.py`
- **plugin.py** (23 connections) — `Backend/binwalk/src/binwalk/core/plugin.py`
- **magic.py** (9 connections) — `Backend/binwalk/src/binwalk/core/magic.py`
- **exceptions.py** (8 connections) — `Backend/binwalk/src/binwalk/core/exceptions.py`
- **BlockFile()** (7 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **unpfs.py** (7 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **settings.py** (6 connections) — `Backend/binwalk/src/binwalk/core/settings.py`
- **gzipvalid.py** (5 connections) — `Backend/binwalk/src/binwalk/plugins/gzipvalid.py`
- **lzmavalid.py** (5 connections) — `Backend/binwalk/src/binwalk/plugins/lzmavalid.py`
- **zlibvalid.py** (5 connections) — `Backend/binwalk/src/binwalk/plugins/zlibvalid.py`
- **display.py** (4 connections) — `Backend/binwalk/src/binwalk/core/display.py`
- **cpio.py** (4 connections) — `Backend/binwalk/src/binwalk/plugins/cpio.py`
- **zlibextract.py** (4 connections) — `Backend/binwalk/src/binwalk/plugins/zlibextract.py`
- **strings()** (3 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **arcadyan.py** (3 connections) — `Backend/binwalk/src/binwalk/plugins/arcadyan.py`
- **ubivalid.py** (3 connections) — `Backend/binwalk/src/binwalk/plugins/ubivalid.py`
- **critical()** (2 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **debug()** (2 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **error()** (2 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **get_libs_path()** (2 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **get_module_path()** (2 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **get_quoted_strings()** (2 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **strip_quoted_strings()** (2 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **warning()** (2 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- *... and 15 more nodes in this community*

## Relationships

- [module / Kwarg / .__init__()](module_-_Kwarg_-_.__init__.md) (22 shared connections)
- [IgnoreFileException / ModuleException / ParserException](IgnoreFileException_-_ModuleException_-_ParserException.md) (9 shared connections)
- [file_md5() / file_size() / Creates a unique file name based on the specified base name. @base_name - The…](file_md5_-_file_size_-_Creates_a_unique_file_name_based_on_the_specified_base_name._@base_name_-_The….md) (5 shared connections)
- [bytes2str() / get_keys() / has_key()](bytes2str_-_get_keys_-_has_key.md) (4 shared connections)
- [PFS / .__enter__() / .entries()](PFS_-_.__enter___-_.entries.md) (4 shared connections)
- [GenericContainer / .__init__() / MathExpression](GenericContainer_-_.__init___-_MathExpression.md) (3 shared connections)
- [dlromfsextract / DlinkROMFSExtractPlugin / .extractor()](dlromfsextract_-_DlinkROMFSExtractPlugin_-_.extractor.md) (2 shared connections)
- [.callback() / Processes the result from all modules. Called for all dependency modules when a… / Plugin](callback_-_Processes_the_result_from_all_modules._Called_for_all_dependency_modules_when_a…_-_Plugin.md) (2 shared connections)
- [idb / end_address() / IDBFileIO](idb_-_end_address_-_IDBFileIO.md) (1 shared connections)
- [statuserver / object / StatusRequestHandler](statuserver_-_object_-_StatusRequestHandler.md) (1 shared connections)
- [get_class_name_from_method() / ExtractDetails / .__init__()](get_class_name_from_method_-_ExtractDetails_-_.__init__.md) (1 shared connections)
- [Display / .add_custom_header() / ._append_to_data_parts()](Display_-_.add_custom_header_-_._append_to_data_parts.md) (1 shared connections)

## Source Files

- `Backend/binwalk/src/binwalk/core/common.py`
- `Backend/binwalk/src/binwalk/core/compat.py`
- `Backend/binwalk/src/binwalk/core/display.py`
- `Backend/binwalk/src/binwalk/core/exceptions.py`
- `Backend/binwalk/src/binwalk/core/magic.py`
- `Backend/binwalk/src/binwalk/core/plugin.py`
- `Backend/binwalk/src/binwalk/core/settings.py`
- `Backend/binwalk/src/binwalk/plugins/arcadyan.py`
- `Backend/binwalk/src/binwalk/plugins/cpio.py`
- `Backend/binwalk/src/binwalk/plugins/gzipvalid.py`
- `Backend/binwalk/src/binwalk/plugins/lzmavalid.py`
- `Backend/binwalk/src/binwalk/plugins/ubivalid.py`
- `Backend/binwalk/src/binwalk/plugins/unjffs2.py`
- `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- `Backend/binwalk/src/binwalk/plugins/zlibextract.py`
- `Backend/binwalk/src/binwalk/plugins/zlibvalid.py`

## Audit Trail

- EXTRACTED: 132 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*