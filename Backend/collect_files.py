import os
import sys
import re
import argparse

def extract_printable_strings(raw_bytes: bytes, min_len: int = 4) -> list:
    """Extracts printable ASCII strings from binary data with noise reduction."""
    pattern = rb"[\x20-\x7E\t\r\n]{" + str(min_len).encode() + rb",}"
    matches = re.findall(pattern, raw_bytes)
    cleaned = []
    seen = set()
    for m in matches:
        s = m.decode("ascii", errors="ignore").strip()
        if not s:
            continue
        # Drop repetitive single-char noise like '00000000'
        if len(set(s)) <= 2 and len(s) > 12:
            continue
        cleaned.append(s)
    return cleaned

def append_file_to_output(file_path: str, out_fh):
    """
    Safely reads any file (UTF-8, Latin-1, binary, UART serial dump, PDF)
    and writes clean, searchable text without crashing or writing error lines.
    """
    out_fh.write(f"file start\n{file_path}\n")
    try:
        is_binary = False
        with open(file_path, "rb") as bf:
            header = bf.read(2048)
            # Check for binary markers or common non-text extensions
            if b"\x00" in header or file_path.lower().endswith((".bin", ".img", ".pdf", ".exe", ".elf", ".so", ".rom", ".tar")):
                is_binary = True

        if is_binary:
            extracted_text = ""
            if file_path.lower().endswith(".pdf"):
                try:
                    import pypdf
                    reader = pypdf.PdfReader(file_path)
                    pages_text = [page.extract_text() or "" for page in reader.pages]
                    extracted_text = "\n".join(pages_text)
                except Exception:
                    pass

            if not extracted_text:
                with open(file_path, "rb") as bf:
                    raw_data = bf.read()
                strings = extract_printable_strings(raw_data, min_len=4)
                extracted_text = "\n".join(strings)

            out_fh.write(extracted_text + "\n")
        else:
            # Text / log file: attempt utf-8 with replace, fallback to latin-1
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as rf:
                    content = rf.read()
            except Exception:
                with open(file_path, "r", encoding="latin-1", errors="replace") as rf:
                    content = rf.read()
            out_fh.write(content + "\n")

    except Exception as e:
        out_fh.write(f"[Notice: Partial parse for {os.path.basename(file_path)}: {e}]\n")
    out_fh.write("file end\n\n")

def collect_all_files(source_folder: str, output_file: str):
    """Walks the source folder and concatenates all files into output_file."""
    with open(output_file, "w", encoding="utf-8") as out_fh:
        for root, dirs, files in os.walk(source_folder):
            for fname in files:
                full_path = os.path.join(root, fname)
                append_file_to_output(full_path, out_fh)

def get_search_results_json(output_file: str, search_str: str, max_results: int = 200) -> list:
    """
    Searches for occurrences of search_str in output_file with accurate
    source filename, file-relative line numbers, and context snippets.
    Prioritizes case-insensitive literal substring matching to avoid regex
    character-class false matches (e.g. '[    0.000000]' or IP addresses),
    while gracefully falling back to regex when explicit patterns are used.
    """
    if not os.path.exists(output_file):
        return []

    if not search_str or not search_str.strip():
        return []

    search_str_clean = search_str.strip()
    search_lower = search_str_clean.lower()

    # Attempt to compile regex for users specifying regex patterns (e.g. ^, $, \d+, .*)
    regex = None
    has_regex_metachars = bool(re.search(r"[\\^$*+?{}|()]", search_str_clean))
    if has_regex_metachars:
        try:
            regex = re.compile(search_str_clean, re.IGNORECASE)
        except re.error:
            regex = None

    with open(output_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    results = []
    current_source = "Unknown"
    current_filename = "Log File"
    in_file = False
    file_line = 0

    i = 0
    total_lines = len(lines)
    while i < total_lines:
        line_raw = lines[i]
        trimmed = line_raw.strip()

        if trimmed == "file start":
            in_file = True
            file_line = 0
            if i + 1 < total_lines:
                current_source = lines[i + 1].strip()
                normalized_path = current_source.replace("\\", "/")
                current_filename = os.path.basename(normalized_path) or "Log File"
                i += 2  # Skip 'file start' and the header filepath line
                continue
            else:
                i += 1
                continue

        if trimmed == "file end":
            in_file = False
            current_source = "Unknown"
            current_filename = "Log File"
            file_line = 0
            i += 1
            continue

        if in_file:
            file_line += 1
            line_lower = line_raw.lower()
            start_col = -1
            end_col = -1

            # 1. Primary: Literal case-insensitive substring search (exact, high-fidelity)
            lit_idx = line_lower.find(search_lower)
            if lit_idx != -1:
                start_col = lit_idx
                end_col = lit_idx + len(search_str_clean)
            elif regex:
                # 2. Secondary: Regex match if literal match was not found
                reg_match = regex.search(line_raw)
                if reg_match:
                    start_col = reg_match.start()
                    end_col = reg_match.end()

            if start_col != -1:
                start = max(0, i - 2)
                end = min(total_lines, i + 3)
                context = [lines[idx].strip() for idx in range(start, end) if lines[idx].strip() not in ("file start", "file end")]

                results.append({
                    "filename": current_filename,
                    "source": current_source,
                    "line": file_line,          # Accurate line number in the original file
                    "merged_line": i + 1,       # Line in the merged combined_files_output.txt
                    "content": trimmed,
                    "start_col": start_col,
                    "end_col": end_col,
                    "context": context
                })

                if len(results) >= max_results:
                    break

        i += 1

    return results

def search_in_output(output_file: str, search_str: str):
    """CLI helper to display search results."""
    results = get_search_results_json(output_file, search_str)
    print(f"\nFound {len(results)} matches for '{search_str}':\n")
    for r in results:
        print(f"[{r['source']}: Line {r['line']}] {r['content']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect files and search with source tracking.")
    parser.add_argument("source", help="Source folder to traverse")
    parser.add_argument("output", help="Output text file")
    parser.add_argument("--search", help="String to search for", default=None)
    args = parser.parse_args()

    if not os.path.isdir(args.source):
        print(f"ERROR: {args.source} is not a valid folder")
        sys.exit(1)

    collect_all_files(args.source, args.output)
    print(f"Done. Output written to: {os.path.abspath(args.output)}")

    if args.search:
        search_in_output(args.output, args.search)
