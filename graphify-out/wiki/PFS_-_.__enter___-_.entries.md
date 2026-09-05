# PFS / .__enter__() / .entries()

> 29 nodes · cohesion 0.09

## Key Concepts

- **PFS** (11 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **PFSCommon** (6 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **PFSNode** (6 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **PFSExtractor** (5 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **._get_node()** (4 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **.entries()** (3 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **._get_fname_len()** (3 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **.__init__()** (3 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **._make_int()** (3 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **._make_short()** (3 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **.extractor()** (3 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **._decode_fname()** (3 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **.__init__()** (3 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **.get_end_of_meta_data()** (2 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **._create_dir_from_fname()** (2 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **.__enter__()** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **.__exit__()** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **.init()** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **object** (1 connections)
- **Returns a 2 byte integer.** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **Returns a 4 byte integer.** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **Class for accessing PFS meta-data.** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **Returns the number of bytes designated for the filename.** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **Reads a chunk of meta data from file and returns a PFSNode.** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- **Returns integer indicating the end of the file system meta data.** (1 connections) — `Backend/binwalk/src/binwalk/plugins/unpfs.py`
- *... and 4 more nodes in this community*

## Relationships

- [common / BlockFile() / critical()](common_-_BlockFile_-_critical.md) (4 shared connections)

## Source Files

- `Backend/binwalk/src/binwalk/plugins/unpfs.py`

## Audit Trail

- EXTRACTED: 39 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*