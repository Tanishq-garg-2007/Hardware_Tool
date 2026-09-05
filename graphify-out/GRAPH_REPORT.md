# Graph Report - Hardware  (2026-09-05)

## Corpus Check
- Large corpus: 255 files · ~6,624,780 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 1514 nodes · 2659 edges · 120 communities (67 shown, 35 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 35 edges (avg confidence: 0.91)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- BootLog_SBOM / _bg_red() / _bold()
- scanner40 / _bg_red() / _bold()
- cv_scanner_40_new / _bg_red() / _bold()
- AnalyzeBootLog / AnalyzeBootLog() / InfoGridItem()
- bytes2str() / get_keys() / has_key()
- main / AnalysisRequest / baud_detect()
- axios / bard-ai / bard-ai-google
- get_class_name_from_method() / ExtractDetails / .__init__()
- IgnoreFileException / ModuleException / ParserException
- common / BlockFile() / critical()
- Module / ._build_display_args() / .clear()
- .callback() / Processes the result from all modules. Called for all dependency modules when a… / Plugin
- setup / AutoCompleteCommand / .finalize_options()
- PFS / .__enter__() / .entries()
- BootLog_Analysis / _check_cpu_compatibility() / _check_upstream_downstream_date()
- bruteforce_uart / check_login() / main()
- FirmAudit / call_Search() / extension_search()
- module / Kwarg / .__init__()
- dlromfsextract / DlinkROMFSExtractPlugin / .extractor()
- main5 / analyse_firm() / analyse_firm_binwalk()
- cve_updater / check_should_update() / count_cves()
- Display / .add_custom_header() / ._append_to_data_parts()
- CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…
- Deflate / .decompress() / .extractor()
- object / Binwalk settings class, used for accessing user and system file paths and… / Get the user's home directory.
- ChatBot / check_and_purge_expired_index() / clean_log_text()
- generate_answer() / get_vectorstore() / Retrieves top-k relevant excerpts with source metadata.
- GenericContainer / .__init__() / MathExpression
- binida / binwalk_t / .init()
- Backend/extractor / create_output_dir() / FirmwarePart
- BootlogInfo / .summary() / _check_bootloader_description()
- assistant_rag / ask_assistant() / get_embeddings()
- file_md5() / file_size() / Creates a unique file name based on the specified base name. @base_name - The…
- _bg_red() / _bold() / _c()
- analysis() / brute_force() / cves_endpoint()
- idb / end_address() / IDBFileIO
- Agent_Analyze / chunk_text() / extract_deterministic_metadata()
- Dependency / .__init__() / Error
- new_capture_uart_boot / force_relay_toggle() / init_gpio()
- analysis() / AnalysisRequest / BootLog
- General / .file_name_filter() / .load()
- deps.sh / find_path() / install_cramfstools()
- CPIOPlugin / .extractor() / ._get_file_name()
- Backend/entropy / analyze_firmware_entropy() / calculate_entropy()
- Hardcoded_Password / FirmwareScanner / .detect_hash_type()
- PowerMod / .__init__() / .run()
- Architecture / .__init__() / ArchResult
- version / binwalk/__init__ / execute()
- HexDiff / ._color_filter() / ._colorize()
- MockGPIO / .cleanup() / .getmode()
- statuserver / object / StatusRequestHandler
- tar / Convert a null-terminated string field to a python string. / Convert a number field to a python number.
- BootLog_Summary / pre_filter_boot_log() / Resolves file path with optional .txt extension and backend directory offsets.
- MockGPIO / .cleanup() / .input()
- new_detect_baud / check_baud_output() / evaluate_baud_quality()
- ChatBotx / ChatBot() / FormattedMessage()
- Called automatically by self.result. / Signature / .init()
- jffs2valid / JFFS2ValidPlugin / ._check_crc()
- check_uart_console / check_console() / check_text_for_console()
- EPSS_CVSS_Extract1 / compute_vulnerabilities() / extract_cvss_from_vuln()
- Forms / COMMON_CHIPS / Forms()
- gzipextract / GzipExtractPlugin / .extractor()
- lzmaextract / LZMAExtractPlugin / .extractor()
- LZMAPlugin / .init() / .is_valid_lzma()
- Helps validate UBI erase count signature results. Checks header CRC and… / UBIValidPlugin / ._check_crc()
- MockGPIO / .output() / .setmode()
- cv_scanner / find_cve() / search_keywords_in_files()
- cv_scanner_40 / find_cve() / search_keywords_in_files()
- EPSS_CVSS_Extract_new / compute_vulnerabilities1() / get_epss()
- firmwalker.sh / getArray() / msg()
- cv_scanner_401 / find_cve() / search_keywords_in_files()
- modified_07122024cv_scanner / find_cve() / search_keywords_in_files()
- test / function_one() / function_two()
- Table / CustomizedTables() / rows
- Layout / Layout() / ResponsiveAppbar
- __main__ / main() / runme()
- ArcadyanDeobfuscator / .extractor() / .init()
- ziphelper / A helper plugin for Zip files to ensure that the Zip archive extraction rule is… / ZipHelperPlugin
- Zlib extractor plugin. / ZLIBExtractPlugin / .extractor()
- detect_kernel_subsystem() / _lookup_commit_prefix() / Map a raw commit-subject prefix to a bootlog subsystem name, or None.
- detect_baud_test / calculate_baud_score() / check_baud_output()
- test_baud / power_off() / power_on()
- old_cv_scner / find_cve() / should_update()
- FileUpload / FileUpload() / settings
- jsconfigon / compilerOptions / baseUrl
- GzipValidPlugin / .scan() / Validates gzip compressed data. Almost identical to zlibvalid.
- Validates zlib compressed data. / ZlibValidPlugin / .scan()
- test_dirtraversal / Open dirtraversal.tar, scan for signatures. Verify that dangerous… / test_dirtraversal()
- test_firmware_cpio / Open firmware.cpio, scan for signatures. Verify that at least one CPIO… / test_firmware_cpio()
- test_firmware_gzip / Open firmware.gzip, scan for signatures. Verify that only one gzip… / test_firmware_gzip()
- test_firmware_jffs2 / Open firmware.jffs2, scan for signatures. Verify that only JFFS2… / test_firmware_jffs2()
- test_firmware_squashfs / Open firmware.squashfs, scan for signatures. Verify that one, and only… / test_firmware_squashfs()
- test_firmware_zip / Open firmware.zip, scan for signatures verify that all (and only)… / test_firmware_zip()
- test_lzma / Open foobar.lzma, scan for signatures. Verify that only one LZMA… / test_lzma()
- check_default_key / check_default_keys() / main()
- detect_baud2 / check_baud_output() / main()
- info / get_size() / 1253656 => '1.20MB' 1253656678 => '1.17GB'
- RAG_CHATBOT / generate_answer() / retrieve()
- Modal / ModalOverlay() / style
- NewAnalyzeBootLog / NewAnalyzeBootLog() / styles
- dump_flash.sh / dump_flash.sh script
- list_flash.sh / list_flash.sh script

## God Nodes (most connected - your core abstractions)
1. `Module` - 41 edges
2. `Extractor` - 33 edges
3. `scan_kernel_cves()` - 23 edges
4. `scan_bootloader_cves()` - 22 edges
5. `Modules` - 22 edges
6. `scan_kernel_cves()` - 21 edges
7. `scan_bootloader_cves()` - 20 edges
8. `Option` - 19 edges
9. `scan_all_cves()` - 19 edges
10. `scan_all_cves()` - 19 edges

## Surprising Connections (you probably didn't know these)
- `analysis()` --indirect_call--> `run()`  [INFERRED]
  Backend/main.py → Backend/Agent_Analyze.py
- `run_scan()` --uses--> `BootlogInfo`  [INFERRED]
  Backend/scanner_wrapper.py → Backend/BootLog_Analysis.py
- `process_multiple_files()` --indirect_call--> `reindex_database()`  [INFERRED]
  Backend/main.py → Backend/ChatBot.py
- `chat_with_file()` --indirect_call--> `generate_answer()`  [INFERRED]
  Backend/main.py → Backend/ChatBot.py
- `scan_firmware()` --uses--> `FirmwareScanner`  [INFERRED]
  Backend/main.py → Backend/Hardcoded_Password.py

## Import Cycles
- None detected.

## Communities (120 total, 35 thin omitted)

### Community 0 - "BootLog_SBOM / _bg_red() / _bold()"
Cohesion: 0.06
Nodes (82): _bg_red(), _bold(), BootlogInfo, _c(), _check_bootloader_description(), _check_cpu_compatibility(), _check_upstream_downstream_date(), chunk_date_range() (+74 more)

### Community 1 - "scanner40 / _bg_red() / _bold()"
Cohesion: 0.06
Nodes (82): _bg_red(), _bold(), BootlogInfo, _c(), _check_bootloader_description(), _check_cpu_compatibility(), _check_upstream_downstream_date(), chunk_date_range() (+74 more)

### Community 2 - "cv_scanner_40_new / _bg_red() / _bold()"
Cohesion: 0.08
Nodes (58): _bg_red(), _bold(), BootlogInfo, _c(), _check_bootloader_description(), _check_cpu_compatibility(), _check_upstream_downstream_date(), _classify_architecture() (+50 more)

### Community 3 - "AnalyzeBootLog / AnalyzeBootLog() / InfoGridItem()"
Cohesion: 0.05
Nodes (24): AnalyzeBootLog(), BasicAccordion(), BootLogViewer(), CaptureBootLogs(), ActionAreaCard(), CheckUARTConsole(), CompleteAnalysisComponent(), formatFileSize() (+16 more)

### Community 4 - "bytes2str() / get_keys() / has_key()"
Cohesion: 0.05
Nodes (27): bytes2str(), get_keys(), has_key(), iterator(), For cross compatibility between Python 2 and Python 3 dictionaries., For cross compatibility between Python 2 and Python 3 dictionaries., For cross compatibility between Python 2 and Python 3 dictionaries., For cross compatibility between Python 2 and Python 3 strings. (+19 more)

### Community 5 - "main / AnalysisRequest / baud_detect()"
Cohesion: 0.08
Nodes (44): AnalysisRequest, baud_detect(), BootLog, BootlogScanPathRequest, capture_boot(), chat_with_file(), ChatRequest, ChipRequest (+36 more)

### Community 6 - "axios / bard-ai / bard-ai-google"
Cohesion: 0.05
Nodes (42): axios, bard-ai, bard-ai-google, @emotion/react, @emotion/styled, eslint, eslint-config-next, browser (+34 more)

### Community 7 - "get_class_name_from_method() / ExtractDetails / .__init__()"
Cohesion: 0.06
Nodes (19): get_class_name_from_method(), ExtractDetails, ExtractInfo, Extractor, object, Extractor class, responsible for extracting files from the target file and…, Adds a set of rules to the extraction rule list. @txtrule - Rule string, or…, Remove all rules that match a specified description. @description - The… (+11 more)

### Community 8 - "IgnoreFileException / ModuleException / ParserException"
Cohesion: 0.06
Nodes (28): IgnoreFileException, ModuleException, ParserException, Exception, Module exception class. Nothing special here except the name., Special exception class used by the load_file plugin method to indicate that…, Exception thrown specifically for signature file parsing errors., Magic (+20 more)

### Community 9 - "common / BlockFile() / critical()"
Cohesion: 0.08
Nodes (23): BlockFile(), critical(), debug(), error(), get_libs_path(), get_module_path(), get_quoted_strings(), Strips out data in between double quotes. @quoted_string - String to strip.… (+15 more)

### Community 10 - "Module / ._build_display_args() / .clear()"
Cohesion: 0.07
Nodes (15): Module, All module classes must be subclassed from this., Invoked at module load time. May be overridden by the module sub-class., Invoked at module load time. May be overridden by the module sub-class., Invoked only for dependency modules immediately prior to starting a new primary…, Invoked prior to self.run. May be overridden by the module sub-class. Returns…, Executes the main module routine. Must be overridden by the module sub-class.…, Validates the result. May be overridden by the module sub-class. @r - The… (+7 more)

### Community 11 - ".callback() / Processes the result from all modules. Called for all dependency modules when a… / Plugin"
Cohesion: 0.08
Nodes (13): Processes the result from all modules. Called for all dependency modules when a…, Plugin, Plugins, object, Obtain a list of all user and system plugin modules. Returns a dictionary of: {…, Class from which all plugin classes are based., Class constructor. @module - A handle to the current module that this plugin is…, Child class should override this if needed. Invoked during plugin… (+5 more)

### Community 12 - "setup / AutoCompleteCommand / .finalize_options()"
Cohesion: 0.09
Nodes (10): AutoCompleteCommand, CleanCommand, find_binwalk_module_paths(), IDAInstallCommand, IDAUnInstallCommand, remove_binwalk_module(), TestCommand, UninstallCommand (+2 more)

### Community 13 - "PFS / .__enter__() / .entries()"
Cohesion: 0.09
Nodes (15): PFS, PFSCommon, PFSExtractor, PFSNode, object, Returns a 2 byte integer., Returns a 4 byte integer., Class for accessing PFS meta-data. (+7 more)

### Community 14 - "BootLog_Analysis / _check_cpu_compatibility() / _check_upstream_downstream_date()"
Cohesion: 0.16
Nodes (24): _check_cpu_compatibility(), _check_upstream_downstream_date(), compare_versions(), _detect_arch_in_text(), _extract_fallback_version(), extract_version_from_cpe(), _format_version_range(), _get_cpe_matches() (+16 more)

### Community 15 - "bruteforce_uart / check_login() / main()"
Cohesion: 0.11
Nodes (22): check_login(), main(), capture_boot_output(), main(), check_baud_output(), evaluate_baud_quality(), Evaluates the quality of captured UART data. Returns 0.0 if the output is…, run_baud_detection() (+14 more)

### Community 16 - "FirmAudit / call_Search() / extension_search()"
Cohesion: 0.09
Nodes (11): call_Search(), ip_Search(), ipWithFileName(), pattern_search(), Exception, Runs the extractor.py script with the specified action and firmware file., Runs the entropy.py script with the specified firmware file and optional block…, run_entropy_script() (+3 more)

### Community 17 - "module / Kwarg / .__init__()"
Cohesion: 0.17
Nodes (11): Kwarg, Option, Convenience wrapper around binwalk.core.module.Modules.help. @fd - An object…, A container class that allows modules to declare command line options., Class constructor. @kwargs - A dictionary of kwarg key-value pairs affected by…, A container class allowing modules to specify their expected __init__ kwarg(s)., Class constructor. @name - Kwarg name. @default - Default kwarg value.…, show_help() (+3 more)

### Community 18 - "dlromfsextract / DlinkROMFSExtractPlugin / .extractor()"
Cohesion: 0.13
Nodes (9): DlinkROMFSExtractPlugin, FileContainer, object, Gzip extractor plugin., # TODO: Support big endian targets., RomFS, RomFSCommon, RomFSDirStruct (+1 more)

### Community 19 - "main5 / analyse_firm() / analyse_firm_binwalk()"
Cohesion: 0.16
Nodes (22): analyse_firm(), analyse_firm_binwalk(), baud_detect(), boot_log(), cap_boot(), cap_boot_show(), cves_endpoint(), down_firm() (+14 more)

### Community 20 - "cve_updater / check_should_update() / count_cves()"
Cohesion: 0.20
Nodes (21): check_should_update(), count_cves(), _download_and_extract_task(), _extract_metrics(), get_cve_by_id(), get_cve_db_dir(), get_database_status(), get_nvd_db_path() (+13 more)

### Community 21 - "Display / .add_custom_header() / ._append_to_data_parts()"
Cohesion: 0.15
Nodes (8): Display, object, Class to handle display of output and writing to log files. This class is…, Intelligently appends data to self.string_parts. For use by self._format., Formats a line of text to fit in the terminal window. For Tim., Configures output formatting, and fitting output to the current terminal width.…, This is a hack, there must be a better way to handle it. In Python3, if the…, Convenience wrapper for self.log which is passed a list of format arguments.

### Community 22 - "CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…"
Cohesion: 0.17
Nodes (18): CVEMatch, _load_cve_database(), Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…, Represents a CVE that matched the bootlog parameters., get_cvss(), Returns CVSS metrics dictionary for a given CVE ID., compute_vulnerabilities(), extract_cvss_from_vuln() (+10 more)

### Community 23 - "Deflate / .decompress() / .extractor()"
Cohesion: 0.16
Nodes (5): Deflate, LZMA, LZMAHeader, object, Finds and extracts raw deflate compression streams.

### Community 24 - "object / Binwalk settings class, used for accessing user and system file paths and… / Get the user's home directory."
Cohesion: 0.18
Nodes (10): object, Binwalk settings class, used for accessing user and system file paths and…, Get the user's home directory., Builds an absolute path and creates the directory and file if they don't…, Gets the full path to the 'subdir/basename' file in the user binwalk directory.…, Gets the full path to the 'subdir/basename' file in the system binwalk…, Class constructor. Enumerates file paths and populates self.paths., Find all user/system magic signature files. @system_only - If True, only the… (+2 more)

### Community 25 - "ChatBot / check_and_purge_expired_index() / clean_log_text()"
Cohesion: 0.24
Nodes (15): check_and_purge_expired_index(), clean_log_text(), compute_file_hash(), get_index_metadata(), Computes SHA-256 hash of a file for content-based cache invalidation., Reads index metadata containing timestamps, expiration, and content hash., Saves index metadata with UTC timestamps., Checks if the indexed files have exceeded the 30-day retention window. If… (+7 more)

### Community 26 - "generate_answer() / get_vectorstore() / Retrieves top-k relevant excerpts with source metadata."
Cohesion: 0.18
Nodes (15): generate_answer(), get_vectorstore(), Retrieves top-k relevant excerpts with source metadata., retrieve(), append_file_to_output(), collect_all_files(), extract_printable_strings(), get_search_results_json() (+7 more)

### Community 27 - "GenericContainer / .__init__() / MathExpression"
Cohesion: 0.14
Nodes (6): GenericContainer, MathExpression, object, Class for safely evaluating mathematical expressions from a string. Stolen…, A class to allow access to strings as if they were read from a file. Used…, StringFile

### Community 28 - "binida / binwalk_t / .init()"
Cohesion: 0.17
Nodes (4): binwalk_t, OpHandler, PLUGIN_ENTRY(), SigHandler

### Community 29 - "Backend/extractor / create_output_dir() / FirmwarePart"
Cohesion: 0.18
Nodes (8): FirmwarePart, find_squashfs(), find_uboot_version(), find_uimage_headers(), find_zip(), get_zip_details(), interpret_squashfs_header(), read_binary()

### Community 30 - "BootlogInfo / .summary() / _check_bootloader_description()"
Cohesion: 0.16
Nodes (14): BootlogInfo, _check_bootloader_description(), _classify_architecture(), _extract_cpu_keywords(), find_cve(), generate_json_report(), main(), parse_args() (+6 more)

### Community 31 - "assistant_rag / ask_assistant() / get_embeddings()"
Cohesion: 0.20
Nodes (13): ask_assistant(), get_embeddings(), get_vectorstore(), index_guide(), Any, Retrieves the most relevant context chunks for a given query. Falls back to raw…, Performs RAG query against the IoT Hardware Auditing Guide. Includes fast-path…, Chunks and indexes the IoT Security Hardware Auditing Guide into ChromaDB. (+5 more)

### Community 32 - "file_md5() / file_size() / Creates a unique file name based on the specified base name. @base_name - The…"
Cohesion: 0.15
Nodes (11): file_md5(), file_size(), Creates a unique file name based on the specified base name. @base_name - The…, Generate an MD5 hash of the specified file. @file_name - The file to hash.…, Obtains the size of a given file. @filename - Path to the file. Returns the…, unique_file_name(), For cross compatibility between Python 2 and Python 3 strings., str2bytes() (+3 more)

### Community 33 - "_bg_red() / _bold() / _c()"
Cohesion: 0.37
Nodes (14): _bg_red(), _bold(), _c(), _cyan(), _dim(), generate_terminal_report(), _green(), _magenta() (+6 more)

### Community 34 - "analysis() / brute_force() / cves_endpoint()"
Cohesion: 0.20
Nodes (14): analysis(), brute_force(), cves_endpoint(), new_cves_endpoint(), process_multiple_files(), post, UploadFile, Accepts a bootlog file from the frontend, saves it temporarily, and passes it… (+6 more)

### Community 35 - "idb / end_address() / IDBFileIO"
Cohesion: 0.18
Nodes (6): end_address(), IDBFileIO, This is used to suppress hashlib exception messages if using the Python…, A custom class to override binwalk.core.common.Blockfile in order to read data…, ShutUpHashlib, start_address()

### Community 36 - "Agent_Analyze / chunk_text() / extract_deterministic_metadata()"
Cohesion: 0.24
Nodes (11): chunk_text(), extract_deterministic_metadata(), extract_strings_from_binary(), filter_relevant_strings(), load_and_clean_file(), Backwards-compatible wrapper that returns extracted lines., Applies regex filtering to keep only lines matching task-specific keywords.…, Splits filtered text into manageable chunks and caps the total chunk count. (+3 more)

### Community 37 - "Dependency / .__init__() / Error"
Cohesion: 0.18
Nodes (9): Dependency, Error, object, A container class for declaring module dependencies., Generic class for storing and accessing scan results., Class constructor. @offset - The file offset of the result. @size - Size of the…, A subclass of binwalk.core.module.Result., Accepts all the same kwargs as binwalk.core.module.Result, but the following… (+1 more)

### Community 38 - "new_capture_uart_boot / force_relay_toggle() / init_gpio()"
Cohesion: 0.23
Nodes (6): force_relay_toggle(), init_gpio(), main(), MockGPIO, new_capture_boot_output(), switch_power()

### Community 39 - "analysis() / AnalysisRequest / BootLog"
Cohesion: 0.21
Nodes (12): analysis(), AnalysisRequest, BootLog, chat_with_file(), ChatRequest, cv_scan(), process_multiple_files(), BaseModel (+4 more)

### Community 40 - "General / .file_name_filter() / .load()"
Cohesion: 0.24
Nodes (5): General, Sets the appropriate verbosity. Must be called after self._test_target_files so…, Checks to see if a file should be scanned based on file name include/exclude…, Opens the specified file with all pertinent configuration settings., Checks if the target files can be opened. Any files that cannot be opened are…

### Community 41 - "deps.sh / find_path() / install_cramfstools()"
Cohesion: 0.38
Nodes (9): find_path(), install_cramfstools(), install_jefferson(), install_pip_package(), install_sasquatch(), install_ubireader(), install_yaffshiv(), lsb_release() (+1 more)

### Community 43 - "Backend/entropy / analyze_firmware_entropy() / calculate_entropy()"
Cohesion: 0.29
Nodes (9): analyze_firmware_entropy(), calculate_entropy(), main(), plot_entropy(), Analyze the entropy of a firmware file in chunks., Save entropy values to a text file., Plot entropy values interactively using plotly and save as HTML., Calculate the Shannon entropy of a data segment. (+1 more)

### Community 44 - "Hardcoded_Password / FirmwareScanner / .detect_hash_type()"
Cohesion: 0.33
Nodes (3): FirmwareScanner, Any, Path

### Community 46 - "Architecture / .__init__() / ArchResult"
Cohesion: 0.25
Nodes (4): Architecture, ArchResult, Disasm, object

### Community 50 - "statuserver / object / StatusRequestHandler"
Cohesion: 0.33
Nodes (4): object, StatusRequestHandler, StatusServer, ThreadedStatusServer

### Community 51 - "tar / Convert a null-terminated string field to a python string. / Convert a number field to a python number."
Cohesion: 0.38
Nodes (3): Convert a null-terminated string field to a python string., Convert a number field to a python number., TarPlugin

### Community 52 - "BootLog_Summary / pre_filter_boot_log() / Resolves file path with optional .txt extension and backend directory offsets."
Cohesion: 0.43
Nodes (6): pre_filter_boot_log(), Resolves file path with optional .txt extension and backend directory offsets., Blazing fast pre-filtering with Python regex: - Eliminates 95% of benign boot…, resolve_bootlog_path(), summarize_boot_log(), summarize()

### Community 54 - "new_detect_baud / check_baud_output() / evaluate_baud_quality()"
Cohesion: 0.48
Nodes (6): check_baud_output(), evaluate_baud_quality(), init_gpio(), new_run_baud_detection(), Evaluates the quality of captured UART data. Returns 0.0 if the output is…, switch_power()

### Community 55 - "ChatBotx / ChatBot() / FormattedMessage()"
Cohesion: 0.38
Nodes (4): ChatBot(), FormattedMessage(), renderInlineFormatted(), theme

### Community 57 - "jffs2valid / JFFS2ValidPlugin / ._check_crc()"
Cohesion: 0.40
Nodes (3): JFFS2ValidPlugin, # TODO: Should this plugin validate the *entire* JFFS2 file system, rather, Helps validate JFFS2 signature results. The JFFS2 signature rules catch obvious…

### Community 58 - "check_uart_console / check_console() / check_text_for_console()"
Cohesion: 0.47
Nodes (5): check_console(), check_text_for_console(), main(), Checks if genuine console prompts or shell indicators are present. Explicitly…, Powers cycles the target, opens the UART port, sends CRLF to prompt for shell,…

### Community 60 - "EPSS_CVSS_Extract1 / compute_vulnerabilities() / extract_cvss_from_vuln()"
Cohesion: 0.73
Nodes (5): compute_vulnerabilities(), extract_cvss_from_vuln(), get_cvss_v2(), get_epss(), Any

### Community 61 - "Forms / COMMON_CHIPS / Forms()"
Cohesion: 0.40
Nodes (3): COMMON_CHIPS, Forms(), SPEED_PRESETS

### Community 67 - "cv_scanner / find_cve() / search_keywords_in_files()"
Cohesion: 0.70
Nodes (4): find_cve(), search_keywords_in_files(), should_update(), update()

### Community 68 - "cv_scanner_40 / find_cve() / search_keywords_in_files()"
Cohesion: 0.70
Nodes (4): find_cve(), search_keywords_in_files(), should_update(), update()

### Community 69 - "EPSS_CVSS_Extract_new / compute_vulnerabilities1() / get_epss()"
Cohesion: 0.70
Nodes (4): compute_vulnerabilities1(), get_epss(), _load_epss_lazy(), Any

### Community 70 - "firmwalker.sh / getArray() / msg()"
Cohesion: 0.70
Nodes (4): getArray(), msg(), firmwalker.sh script, usage()

### Community 71 - "cv_scanner_401 / find_cve() / search_keywords_in_files()"
Cohesion: 0.70
Nodes (4): find_cve(), search_keywords_in_files(), should_update(), update()

### Community 72 - "modified_07122024cv_scanner / find_cve() / search_keywords_in_files()"
Cohesion: 0.70
Nodes (4): find_cve(), search_keywords_in_files(), should_update(), update()

### Community 73 - "test / function_one() / function_two()"
Cohesion: 0.60
Nodes (4): function_one(), function_two(), index(), get

### Community 74 - "Table / CustomizedTables() / rows"
Cohesion: 0.40
Nodes (3): rows, StyledTableCell, StyledTableRow

### Community 80 - "detect_kernel_subsystem() / _lookup_commit_prefix() / Map a raw commit-subject prefix to a bootlog subsystem name, or None."
Cohesion: 0.50
Nodes (4): detect_kernel_subsystem(), _lookup_commit_prefix(), Map a raw commit-subject prefix to a bootlog subsystem name, or None., Determine the Linux kernel subsystem affected by a CVE. Priority chain: commit-…

### Community 81 - "detect_baud_test / calculate_baud_score() / check_baud_output()"
Cohesion: 0.83
Nodes (3): calculate_baud_score(), check_baud_output(), run_baud_detection()

### Community 82 - "test_baud / power_off() / power_on()"
Cohesion: 0.83
Nodes (3): power_off(), power_on(), test_baud()

### Community 83 - "old_cv_scner / find_cve() / should_update()"
Cohesion: 0.83
Nodes (3): find_cve(), should_update(), update()

### Community 85 - "jsconfigon / compilerOptions / baseUrl"
Cohesion: 0.50
Nodes (3): compilerOptions, baseUrl, paths

## Knowledge Gaps
- **41 isolated node(s):** `Unjffs2DepreciatedPlugin`, `dump_flash.sh script`, `MockRPi`, `list_flash.sh script`, `MockRPi` (+36 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 515 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **35 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `dotenv` connect `CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…` to `ChatBot / check_and_purge_expired_index() / clean_log_text()`, `cve_updater / check_should_update() / count_cves()`, `main / AnalysisRequest / baud_detect()`, `assistant_rag / ask_assistant() / get_embeddings()`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._
- **Why does `dependencies` connect `axios / bard-ai / bard-ai-google` to `CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **Why does `dotenv` connect `CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…` to `axios / bard-ai / bard-ai-google`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Are the 3 inferred relationships involving `Extractor` (e.g. with `ModuleException` and `Kwarg`) actually correct?**
  _`Extractor` has 3 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Unjffs2DepreciatedPlugin`, `dump_flash.sh script`, `MockRPi` to the rest of the system?**
  _41 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `BootLog_SBOM / _bg_red() / _bold()` be split into smaller, more focused modules?**
  _Cohesion score 0.05636114911080711 - nodes in this community are weakly interconnected._
- **Should `scanner40 / _bg_red() / _bold()` be split into smaller, more focused modules?**
  _Cohesion score 0.05636114911080711 - nodes in this community are weakly interconnected._