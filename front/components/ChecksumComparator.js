import React, { useState, useRef } from "react";
import {
  Box,
  Typography,
  Paper,
  Button,
  Grid,
  Alert,
  CircularProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
} from "@mui/material";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import CompareArrowsIcon from "@mui/icons-material/CompareArrows";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import HighlightOffIcon from "@mui/icons-material/HighlightOff";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import InsertDriveFileIcon from "@mui/icons-material/InsertDriveFile";

export default function ChecksumComparator() {
  const [file1, setFile1] = useState(null);
  const [file2, setFile2] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [copiedKey, setCopiedKey] = useState(null);

  const fileInputRef1 = useRef(null);
  const fileInputRef2 = useRef(null);

  const handleFileChange = (num, e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (num === 1) {
      setFile1(file);
    } else {
      setFile2(file);
    }
    setResult(null);
    setError("");
  };

  const handleClear = (num) => {
    if (num === 1) {
      setFile1(null);
      if (fileInputRef1.current) fileInputRef1.current.value = "";
    } else {
      setFile2(null);
      if (fileInputRef2.current) fileInputRef2.current.value = "";
    }
    setResult(null);
    setError("");
  };

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const handleCompare = async () => {
    if (!file1 || !file2) {
      setError("Please select both files to compare their checksums.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    const formData = new FormData();
    formData.append("file1", file1);
    formData.append("file2", file2);

    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${apiBase}/compare-checksums`, {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || data.message || "Failed to compare checksums.");
      }

      setResult(data);
    } catch (err) {
      setError(err.message || "An error occurred while comparing files.");
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text, key) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  };

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 3.5,
        borderRadius: "20px",
        backgroundColor: "background.paper",
        boxShadow: "0 4px 20px rgba(0, 0, 0, 0.02)",
        borderColor: "divider",
        display: "flex",
        flexDirection: "column",
        gap: 3,
      }}
    >
      {/* Title & Description */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 1 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 700, color: "text.primary", display: "flex", alignItems: "center", gap: 1 }}>
            <FingerprintIcon color="primary" /> Binary Image Checksum & Comparison
          </Typography>
          <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
            Upload two firmware binaries (.bin, .rom, .img) to verify readout integrity, calculate cryptographic hashes, and check if both files are identical.
          </Typography>
        </Box>
        {/* <Chip
          label="SHA-256 • MD5 • SHA-1 • CRC32"
          size="small"
          color="primary"
          variant="outlined"
          sx={{ fontWeight: 600, fontSize: "11px", borderRadius: "8px" }}
        /> */}
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" onClose={() => setError("")} sx={{ borderRadius: "12px" }}>
          {error}
        </Alert>
      )}

      {/* File Upload Inputs */}
      <Grid container spacing={2.5}>
        {/* File 1 Upload Box */}
        <Grid item xs={12} sm={6}>
          <Paper
            variant="outlined"
            sx={{
              p: 2.5,
              borderRadius: "16px",
              backgroundColor: "background.default",
              borderColor: file1 ? "primary.main" : "divider",
              borderWidth: file1 ? "2px" : "1px",
              display: "flex",
              flexDirection: "column",
              gap: 1.5,
              minHeight: "160px",
              justifyContent: "space-between",
              transition: "border-color 0.2s ease-in-out",
            }}
          >
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.primary" }}>
                File 1 (Reference .bin)
              </Typography>
              {file1 && (
                <IconButton size="small" onClick={() => handleClear(1)} color="error" title="Remove File 1">
                  <DeleteOutlineIcon fontSize="small" />
                </IconButton>
              )}
            </Box>

            {file1 ? (
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 1.5, bgcolor: "background.paper", borderRadius: "10px", border: "1px solid", borderColor: "divider" }}>
                <InsertDriveFileIcon color="primary" sx={{ fontSize: 32 }} />
                <Box sx={{ overflow: "hidden" }}>
                  <Typography variant="body2" sx={{ fontWeight: 700, wordBreak: "break-all" }}>
                    {file1.name}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    Size: {formatSize(file1.size)}
                  </Typography>
                </Box>
              </Box>
            ) : (
              <Box sx={{ textAlign: "center", py: 2 }}>
                <CloudUploadIcon sx={{ fontSize: 36, color: "text.secondary", mb: 0.5 }} />
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  Select or drag first .bin image
                </Typography>
              </Box>
            )}

            <Button
              component="label"
              variant={file1 ? "outlined" : "contained"}
              color="primary"
              startIcon={<CloudUploadIcon />}
              sx={{ borderRadius: "10px", fontWeight: 600, textTransform: "none", py: 0.8 }}
            >
              {file1 ? "Change File 1" : "Upload File 1 (.bin)"}
              <input
                ref={fileInputRef1}
                type="file"
                hidden
                accept=".bin,.rom,.img,.raw,.hex,*"
                onChange={(e) => handleFileChange(1, e)}
              />
            </Button>
          </Paper>
        </Grid>

        {/* File 2 Upload Box */}
        <Grid item xs={12} sm={6}>
          <Paper
            variant="outlined"
            sx={{
              p: 2.5,
              borderRadius: "16px",
              backgroundColor: "background.default",
              borderColor: file2 ? "primary.main" : "divider",
              borderWidth: file2 ? "2px" : "1px",
              display: "flex",
              flexDirection: "column",
              gap: 1.5,
              minHeight: "160px",
              justifyContent: "space-between",
              transition: "border-color 0.2s ease-in-out",
            }}
          >
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.primary" }}>
                File 2 (Verification .bin)
              </Typography>
              {file2 && (
                <IconButton size="small" onClick={() => handleClear(2)} color="error" title="Remove File 2">
                  <DeleteOutlineIcon fontSize="small" />
                </IconButton>
              )}
            </Box>

            {file2 ? (
              <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, p: 1.5, bgcolor: "background.paper", borderRadius: "10px", border: "1px solid", borderColor: "divider" }}>
                <InsertDriveFileIcon color="primary" sx={{ fontSize: 32 }} />
                <Box sx={{ overflow: "hidden" }}>
                  <Typography variant="body2" sx={{ fontWeight: 700, wordBreak: "break-all" }}>
                    {file2.name}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    Size: {formatSize(file2.size)}
                  </Typography>
                </Box>
              </Box>
            ) : (
              <Box sx={{ textAlign: "center", py: 2 }}>
                <CloudUploadIcon sx={{ fontSize: 36, color: "text.secondary", mb: 0.5 }} />
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                  Select or drag second .bin image
                </Typography>
              </Box>
            )}

            <Button
              component="label"
              variant={file2 ? "outlined" : "contained"}
              color="primary"
              startIcon={<CloudUploadIcon />}
              sx={{ borderRadius: "10px", fontWeight: 600, textTransform: "none", py: 0.8 }}
            >
              {file2 ? "Change File 2" : "Upload File 2 (.bin)"}
              <input
                ref={fileInputRef2}
                type="file"
                hidden
                accept=".bin,.rom,.img,.raw,.hex,*"
                onChange={(e) => handleFileChange(2, e)}
              />
            </Button>
          </Paper>
        </Grid>
      </Grid>

      {/* Action Button */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
        <Button
          variant="contained"
          size="large"
          onClick={handleCompare}
          disabled={loading || !file1 || !file2}
          startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <CompareArrowsIcon />}
          sx={{
            borderRadius: "12px",
            py: 1.2,
            px: 4,
            fontWeight: 700,
            fontSize: "14px",
            color: "#FFFFFF !important",
            backgroundColor: "#2563EB",
            backgroundImage: "linear-gradient(135deg, #2563EB 0%, #1D4ED8 100%)",
            boxShadow: "0 4px 14px rgba(37, 99, 235, 0.35)",
            "&:hover": {
              backgroundColor: "#1D4ED8",
              backgroundImage: "linear-gradient(135deg, #1D4ED8 0%, #1E40AF 100%)",
              boxShadow: "0 6px 20px rgba(37, 99, 235, 0.45)",
            },
            "&.Mui-disabled": {
              color: "#FFFFFF !important",
              opacity: 0.6,
              backgroundImage: "linear-gradient(135deg, #60A5FA 0%, #3B82F6 100%)",
              backgroundColor: "#3B82F6",
            },
          }}
        >
          {loading ? "Calculating Checksums..." : "Calculate & Compare Checksums"}
        </Button>

        {(file1 || file2 || result) && (
          <Button
            variant="text"
            color="inherit"
            onClick={() => {
              handleClear(1);
              handleClear(2);
            }}
            sx={{ borderRadius: "10px", color: "text.secondary", fontWeight: 600 }}
          >
            Reset
          </Button>
        )}
      </Box>

      {/* ── Comparison Results Section ── */}
      {result && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 2.5, mt: 1 }}>
          {/* Main Verdict Banner */}
          {result.is_same ? (
            <Paper
              elevation={0}
              sx={{
                p: 2.5,
                borderRadius: "14px",
                backgroundColor: "#F0FDF4",
                border: "2px solid #86EFAC",
                display: "flex",
                alignItems: "center",
                gap: 2,
              }}
            >
              <CheckCircleOutlineIcon sx={{ fontSize: 36, color: "#16A34A" }} />
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 800, color: "#15803D", letterSpacing: "-0.3px" }}>
                  Both files are same.
                </Typography>
                <Typography variant="body2" sx={{ color: "#166534", fontWeight: 500 }}>
                  Cryptographic checksums match 100% (Bit-for-bit identical firmware dumps verified).
                </Typography>
              </Box>
            </Paper>
          ) : (
            <Paper
              elevation={0}
              sx={{
                p: 2.5,
                borderRadius: "14px",
                backgroundColor: "#FEF2F2",
                border: "2px solid #FCA5A5",
                display: "flex",
                alignItems: "center",
                gap: 2,
              }}
            >
              <HighlightOffIcon sx={{ fontSize: 36, color: "#DC2626" }} />
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 800, color: "#B91C1C", letterSpacing: "-0.3px" }}>
                  Files are different.
                </Typography>
                <Typography variant="body2" sx={{ color: "#991B1B", fontWeight: 500 }}>
                  Checksum mismatch detected. The two files have different binary contents or lengths.
                </Typography>
              </Box>
            </Paper>
          )}

          {/* Detailed Checksums Table */}
          <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: "14px", borderColor: "divider" }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ backgroundColor: "background.default" }}>
                  <TableCell sx={{ fontWeight: 700, width: "120px" }}>Algorithm</TableCell>
                  <TableCell sx={{ fontWeight: 700, minWidth: "220px" }}>
                    File 1: {result.file1.filename} ({result.file1.size_formatted})
                  </TableCell>
                  <TableCell sx={{ fontWeight: 700, minWidth: "220px" }}>
                    File 2: {result.file2.filename} ({result.file2.size_formatted})
                  </TableCell>
                  <TableCell sx={{ fontWeight: 700, width: "100px", textAlign: "center" }}>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {/* SHA-256 */}
                <ChecksumRow
                  label="SHA-256"
                  val1={result.file1.sha256}
                  val2={result.file2.sha256}
                  isMatch={result.comparison.sha256_match}
                  onCopy={handleCopy}
                  copiedKey={copiedKey}
                />
                {/* MD5 */}
                <ChecksumRow
                  label="MD5"
                  val1={result.file1.md5}
                  val2={result.file2.md5}
                  isMatch={result.comparison.md5_match}
                  onCopy={handleCopy}
                  copiedKey={copiedKey}
                />
                {/* SHA-1 */}
                <ChecksumRow
                  label="SHA-1"
                  val1={result.file1.sha1}
                  val2={result.file2.sha1}
                  isMatch={result.comparison.sha1_match}
                  onCopy={handleCopy}
                  copiedKey={copiedKey}
                />
                {/* CRC32 */}
                <ChecksumRow
                  label="CRC32"
                  val1={result.file1.crc32}
                  val2={result.file2.crc32}
                  isMatch={result.comparison.crc32_match}
                  onCopy={handleCopy}
                  copiedKey={copiedKey}
                />
                {/* Size */}
                <TableRow hover>
                  <TableCell sx={{ fontWeight: 700, color: "text.secondary" }}>Size (Bytes)</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "12px" }}>
                    {result.file1.size_bytes.toLocaleString()} bytes
                  </TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "12px" }}>
                    {result.file2.size_bytes.toLocaleString()} bytes
                  </TableCell>
                  <TableCell sx={{ textAlign: "center" }}>
                    <MatchChip isMatch={result.comparison.size_match} />
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}
    </Paper>
  );
}

function ChecksumRow({ label, val1, val2, isMatch, onCopy, copiedKey }) {
  const key1 = `${label}_1`;
  const key2 = `${label}_2`;

  return (
    <TableRow hover>
      <TableCell sx={{ fontWeight: 700, color: "text.primary" }}>{label}</TableCell>
      <TableCell sx={{ fontFamily: "monospace", fontSize: "12px", wordBreak: "break-all" }}>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 1 }}>
          <span>{val1}</span>
          <Tooltip title={copiedKey === key1 ? "Copied!" : "Copy hash"} arrow>
            <IconButton size="small" onClick={() => onCopy(val1, key1)}>
              <ContentCopyIcon sx={{ fontSize: "14px" }} />
            </IconButton>
          </Tooltip>
        </Box>
      </TableCell>
      <TableCell sx={{ fontFamily: "monospace", fontSize: "12px", wordBreak: "break-all" }}>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 1 }}>
          <span>{val2}</span>
          <Tooltip title={copiedKey === key2 ? "Copied!" : "Copy hash"} arrow>
            <IconButton size="small" onClick={() => onCopy(val2, key2)}>
              <ContentCopyIcon sx={{ fontSize: "14px" }} />
            </IconButton>
          </Tooltip>
        </Box>
      </TableCell>
      <TableCell sx={{ textAlign: "center" }}>
        <MatchChip isMatch={isMatch} />
      </TableCell>
    </TableRow>
  );
}

function MatchChip({ isMatch }) {
  return (
    <Chip
      size="small"
      label={isMatch ? "MATCH" : "DIFF"}
      sx={{
        fontWeight: 700,
        fontSize: "10px",
        borderRadius: "6px",
        backgroundColor: isMatch ? "#DCFCE7" : "#FEE2E2",
        color: isMatch ? "#15803D" : "#DC2626",
      }}
    />
  );
}
