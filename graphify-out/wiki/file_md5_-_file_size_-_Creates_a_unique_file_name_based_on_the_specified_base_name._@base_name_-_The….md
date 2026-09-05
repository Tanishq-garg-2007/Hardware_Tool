# file_md5() / file_size() / Creates a unique file name based on the specified base name. @base_name - The…

> 14 nodes · cohesion 0.15

## Key Concepts

- **.extract()** (9 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`
- **._dd()** (6 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`
- **unique_file_name()** (5 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **.build_output_directory()** (5 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`
- **file_md5()** (4 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **file_size()** (4 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **str2bytes()** (4 connections) — `Backend/binwalk/src/binwalk/core/compat.py`
- **Creates a unique file name based on the specified base name. @base_name - The…** (1 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **Generate an MD5 hash of the specified file. @file_name - The file to hash.…** (1 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **Obtains the size of a given file. @filename - Path to the file. Returns the…** (1 connections) — `Backend/binwalk/src/binwalk/core/common.py`
- **For cross compatibility between Python 2 and Python 3 strings.** (1 connections) — `Backend/binwalk/src/binwalk/core/compat.py`
- **Set the output directory for extracted files. @path - The path to the file that…** (1 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`
- **Extract an embedded file from the target file, if it matches an extract rule.…** (1 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`
- **Extracts a file embedded inside the target file. @file_name - Path to the…** (1 connections) — `Backend/binwalk/src/binwalk/modules/extractor.py`

## Relationships

- [get_class_name_from_method() / ExtractDetails / .__init__()](get_class_name_from_method_-_ExtractDetails_-_.__init__.md) (6 shared connections)
- [common / BlockFile() / critical()](common_-_BlockFile_-_critical.md) (5 shared connections)
- [module / Kwarg / .__init__()](module_-_Kwarg_-_.__init__.md) (3 shared connections)
- [bytes2str() / get_keys() / has_key()](bytes2str_-_get_keys_-_has_key.md) (2 shared connections)

## Source Files

- `Backend/binwalk/src/binwalk/core/common.py`
- `Backend/binwalk/src/binwalk/core/compat.py`
- `Backend/binwalk/src/binwalk/modules/extractor.py`

## Audit Trail

- EXTRACTED: 30 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*