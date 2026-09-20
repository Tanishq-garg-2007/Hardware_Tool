import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/router";
import {
  Box,
  Typography,
  TextField,
  Button,
  Paper,
  Chip,
  Grid,
  CircularProgress,
  LinearProgress,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Divider,
  Tooltip,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import SecurityIcon from "@mui/icons-material/Security";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import SyncIcon from "@mui/icons-material/Sync";
import StorageIcon from "@mui/icons-material/Storage";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CancelIcon from "@mui/icons-material/Cancel";
import BootlogScanResults from "./BootlogScanResults";

export default function AnalyzeBootLog({ onBack }) {
  const router = useRouter();

  const handleBack = () => {
    if (onBack) {
      onBack();
    } else if (typeof window !== 'undefined' && window.history.length > 1) {
      router.back();
    } else if (router?.query?.mode) {
      router.push(`/dashboard?mode=${router.query.mode}`);
    } else {
      router.push("/dashboard");
    }
  };

  const [directoryPath, setDirectoryPath] = useState("");
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [uploadingFile, setUploadingFile] = useState(false);
  const [uploadMsg, setUploadMsg] = useState(null);
  const fileInputRef = useRef(null);
  const [error, setError] = useState("");

  // CVE Database Status & Updater State
  const [dbStatus, setDbStatus] = useState(null);
  const [dbLoading, setDbLoading] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);
  const [updateMsg, setUpdateMsg] = useState("");
  const pollIntervalRef = useRef(null);

  // Fetch CVE Database Status
  const fetchDbStatus = async () => {
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${apiBase}/cve-database/status`);
      if (res.ok) {
        const data = await res.json();
        setDbStatus(data);
        return data;
      }
    } catch (err) {
      console.error("Failed to fetch CVE database status:", err);
    }
    return null;
  };

  useEffect(() => {
    fetchDbStatus();
  }, []);

  // Poll when background updater is actively running
  useEffect(() => {
    if (dbStatus?.updater_state?.is_updating) {
      if (!pollIntervalRef.current) {
        pollIntervalRef.current = setInterval(async () => {
          const fresh = await fetchDbStatus();
          if (fresh && !fresh.updater_state?.is_updating) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
        }, 2000);
      }
    } else {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [dbStatus?.updater_state?.is_updating]);

  // Handle Trigger Update
  const handleUpdateDatabase = async (force = false) => {
    setDbLoading(true);
    setUpdateMsg("");
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${apiBase}/cve-database/update`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ force }),
      });
      const data = await res.json();
      setUpdateMsg(data.message || "Update triggered.");
      await fetchDbStatus();
    } catch (err) {
      setUpdateMsg(`Update request error: ${err.message}`);
    } finally {
      setDbLoading(false);
    }
  };

  // Handle Cancel Update
  const handleCancelUpdate = async () => {
    setCancelLoading(true);
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${apiBase}/cve-database/cancel`, {
        method: "POST",
      });
      const data = await res.json();
      setUpdateMsg(data.message || "Cancellation requested.");
      await fetchDbStatus();
    } catch (err) {
      setUpdateMsg(`Cancel error: ${err.message}`);
    } finally {
      setCancelLoading(false);
    }
  };

  // Handle Bootlog File Upload
  const handleBootlogFileUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setUploadingFile(true);
    setError("");
    setUploadMsg(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${apiBase}/upload-bootlog`, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        let errMsg = "Upload failed.";
        try {
          const errData = await res.json();
          if (errData.detail) errMsg = errData.detail;
        } catch (_) {}
        throw new Error(errMsg);
      }

      const data = await res.json();
      const newPath = data.path || data.relative_path || data.file_path;
      setDirectoryPath(newPath);
      setUploadMsg({
        type: "success",
        text: `Uploaded "${file.name}" successfully. Ready to run analysis.`,
      });
    } catch (err) {
      setUploadMsg({
        type: "error",
        text: `Failed to upload bootlog: ${err.message}`,
      });
    } finally {
      setUploadingFile(false);
      if (event.target) {
        event.target.value = "";
      }
    }
  };

  const handleAnalyze = async (customPath) => {
    const targetPath = (typeof customPath === "string" ? customPath : directoryPath).trim();
    if (!targetPath) {
      setError("Please enter a target file or directory path first.");
      return;
    }

    setError("");
    setLoading(true);
    setScanData(null);

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/scan-path`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target_path: targetPath,
          force_db_update: false,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || data.message || "Failed to fetch scan results from backend.");
      }

      setScanData(data.data);
    } catch (err) {
      setError(err.message || "An error occurred while connecting to the scan service.");
    } finally {
      setLoading(false);
    }
  };

  const formatVal = (val) => {
    if (!val || val === "N/A") return "N/A";
    if (Array.isArray(val)) return val.length > 0 ? val.join(", ") : "N/A";
    return val;
  };

  const getSeverityChip = (severity, score) => {
    const s = (severity || "").toUpperCase();
    let bg = "#F1F5F9";
    let text = "#475569";

    if (s.includes("CRIT") || score >= 9.0) {
      bg = "#FEE2E2";
      text = "#DC2626";
    } else if (s.includes("HIGH") || score >= 7.0) {
      bg = "#FFEDD5";
      text = "#EA580C";
    } else if (s.includes("MED") || score >= 4.0) {
      bg = "#FEF3C7";
      text = "#D97706";
    } else if (s.includes("LOW")) {
      bg = "#E0F2FE";
      text = "#0284C7";
    }

    return (
      <Box
        component="span"
        sx={{
          backgroundColor: bg,
          color: text,
          fontWeight: 700,
          fontSize: "12px",
          px: 1.5,
          py: 0.5,
          borderRadius: "8px",
          display: "inline-block",
        }}
      >
        {severity || (score ? `Score ${score}` : "UNRATED")}
      </Box>
    );
  };

  const isUpdating = dbStatus?.updater_state?.is_updating;
  const progressPercent = dbStatus?.updater_state?.progress_percent || 0;
  const statusMessage = dbStatus?.updater_state?.status_message || "";

  return (
    <Box sx={{ width: "100%", display: "flex", flexDirection: "column", gap: 3 }}>
      {/* Header & Title */}
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 700, color: "text.primary", mb: 0.5, letterSpacing: "-0.5px" }}>
          Bootlog CVE Risk Analyzer
        </Typography>
        <Typography variant="body2" sx={{ color: "text.secondary" }}>
          Deep structural analysis, hardware signature extraction, and CVE vulnerability matching across bootlogs.
        </Typography>
      </Box>

      {/* ── CVE DATABASE STATUS & UPDATER PANEL ── */}
      <Paper
        elevation={0}
        sx={{
          p: 2.5,
          borderRadius: "18px",
          backgroundColor: "background.default",
          border: "1px solid",
          borderColor: "divider",
          boxShadow: "0 2px 10px rgba(0,0,0,0.02)",
          display: "flex",
          flexDirection: "column",
          gap: 2,
        }}
      >
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            <StorageIcon color="primary" sx={{ fontSize: 28 }} />
            <Box>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "text.primary" }}>
                  Active CVE Database: {dbStatus?.database_type || "NIST NVD 2.0 (Offline Database)"}
                </Typography>
                <Tooltip
                  title={
                    dbStatus?.explanation ||
                    "You are using the official NIST NVD 2.0 offline SQLite database with full CVSS v2/v3/v4 scores and CPE mappings."
                  }
                  arrow
                >
                  <InfoOutlinedIcon sx={{ fontSize: 18, color: "primary.main", cursor: "pointer" }} />
                </Tooltip>
              </Box>
              <Typography variant="caption" sx={{ color: "text.secondary" }}>
                Source: <strong>NIST National Vulnerability Database (NVD)</strong>
              </Typography>
            </Box>
          </Box>

          <Box sx={{ display: "flex", gap: 1.5, alignItems: "center" }}>
            {isUpdating ? (
              <>
                <Button
                  variant="contained"
                  color="primary"
                  size="small"
                  disabled
                  startIcon={<CircularProgress size={16} color="inherit" />}
                  sx={{ borderRadius: "10px", fontWeight: 600 }}
                >
                  Updating...
                </Button>
                <Button
                  variant="outlined"
                  color="error"
                  size="small"
                  onClick={handleCancelUpdate}
                  disabled={cancelLoading}
                  startIcon={cancelLoading ? <CircularProgress size={16} color="inherit" /> : <CancelIcon />}
                  sx={{
                    borderRadius: "10px",
                    fontWeight: 600,
                    borderColor: "error.main",
                    "&:hover": {
                      backgroundColor: "rgba(239, 68, 68, 0.08)",
                      borderColor: "error.dark",
                    },
                  }}
                >
                  {cancelLoading ? "Cancelling..." : "Cancel Update"}
                </Button>
              </>
            ) : (
              <>
                <Button
                  variant="contained"
                  color="primary"
                  size="small"
                  onClick={() => handleUpdateDatabase(false)}
                  disabled={dbLoading}
                  startIcon={<SyncIcon />}
                  sx={{ borderRadius: "10px", fontWeight: 600 }}
                >
                  Update Database
                </Button>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => handleUpdateDatabase(true)}
                  disabled={dbLoading}
                  sx={{ borderRadius: "10px", fontWeight: 600, color: "text.secondary" }}
                >
                  Force Sync
                </Button>
              </>
            )}
          </Box>
        </Box>

        {/* Database Stats Row */}
        <Grid container spacing={1.5}>
          <Grid item xs={12} sm={4}>
            <Box sx={{ p: 1.5, borderRadius: "10px", backgroundColor: "background.paper", border: "1px solid", borderColor: "divider" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500, display: "block" }}>
                Database Provider
              </Typography>
              <Typography variant="body2" sx={{ fontWeight: 700, color: "text.primary" }}>
                {dbStatus?.database_type || "NIST NVD 2.0"}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} sm={4}>
            <Box sx={{ p: 1.5, borderRadius: "10px", backgroundColor: "background.paper", border: "1px solid", borderColor: "divider" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500, display: "block" }}>
                Total Records Loaded
              </Typography>
              <Typography variant="body2" sx={{ fontWeight: 700, color: "primary.main" }}>
                {dbStatus ? `${dbStatus.total_cves_loaded.toLocaleString()} CVEs` : "Loading..."}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} sm={4}>
            <Box sx={{ p: 1.5, borderRadius: "10px", backgroundColor: "background.paper", border: "1px solid", borderColor: "divider" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500, display: "block" }}>
                Last Updated
              </Typography>
              <Typography variant="body2" sx={{ fontWeight: 700, color: "text.primary" }}>
                {dbStatus?.last_updated || "Never"}
              </Typography>
            </Box>
          </Grid>
        </Grid>

        {/* Real-time Update Progress Bar */}
        {isUpdating && (
          <Box sx={{ mt: 1 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.5 }}>
              <Typography variant="caption" sx={{ fontWeight: 600, color: "primary.main" }}>
                {statusMessage}
              </Typography>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Typography variant="caption" sx={{ fontWeight: 700, color: "text.primary" }}>
                  {progressPercent}%
                </Typography>
                <Button
                  size="small"
                  color="error"
                  variant="text"
                  onClick={handleCancelUpdate}
                  disabled={cancelLoading}
                  sx={{ fontSize: "11px", py: 0, px: 1, minWidth: "auto", fontWeight: 600, textTransform: "none" }}
                >
                  Cancel
                </Button>
              </Box>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{ height: 8, borderRadius: 4, backgroundColor: "action.hover" }}
            />
          </Box>
        )}

        {updateMsg && !isUpdating && (
          <Alert
            severity={
              updateMsg.toLowerCase().includes("offline") ||
              updateMsg.toLowerCase().includes("error") ||
              updateMsg.toLowerCase().includes("no active internet")
                ? "warning"
                : "info"
            }
            onClose={() => setUpdateMsg("")}
            sx={{ py: 0.5, borderRadius: "10px" }}
          >
            {updateMsg}
          </Alert>
        )}
      </Paper>

      {/* Target Path Controls */}
      <Paper
        variant="outlined"
        sx={{
          p: 2.5,
          borderRadius: "16px",
          backgroundColor: "background.default",
          borderColor: "divider",
          display: "flex",
          flexDirection: "column",
          gap: 2,
        }}
      >
        <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "text.primary" }}>
          Target Bootlog Path or Directory
        </Typography>
        <Box sx={{ display: "flex", gap: 1.5, flexWrap: { xs: "wrap", sm: "nowrap" } }}>
          <TextField
            fullWidth
            size="small"
            placeholder="Enter file/directory path or upload a bootlog file..."
            value={directoryPath}
            onChange={(e) => setDirectoryPath(e.target.value)}
            sx={{
              "& .MuiOutlinedInput-root": {
                borderRadius: "12px",
                backgroundColor: "background.paper",
              },
            }}
          />
          <Button
            component="label"
            variant="outlined"
            disabled={uploadingFile || loading}
            startIcon={uploadingFile ? <CircularProgress size={18} color="inherit" /> : <CloudUploadIcon />}
            sx={{
              px: 2.5,
              borderRadius: "12px",
              fontWeight: 600,
              whiteSpace: "nowrap",
              minWidth: "150px",
              color: "text.primary",
              borderColor: "divider",
              backgroundColor: "background.paper",
              "&:hover": {
                borderColor: "primary.main",
                backgroundColor: "action.hover",
              },
            }}
          >
            {uploadingFile ? "Uploading..." : "Upload File"}
            <input
              type="file"
              hidden
              accept=".txt,.log,.raw,text/plain"
              ref={fileInputRef}
              onChange={handleBootlogFileUpload}
            />
          </Button>
          <Button
            variant="contained"
            color="primary"
            onClick={() => handleAnalyze()}
            disabled={loading || uploadingFile}
            startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
            sx={{
              px: 3,
              borderRadius: "12px",
              fontWeight: 600,
              whiteSpace: "nowrap",
              minWidth: "160px",
            }}
          >
            {loading ? "Scanning..." : "Run Analysis"}
          </Button>
        </Box>
        {uploadMsg && (
          <Alert
            severity={uploadMsg.type}
            onClose={() => setUploadMsg(null)}
            sx={{ py: 0.5, borderRadius: "10px" }}
          >
            {uploadMsg.text}
          </Alert>
        )}
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ borderRadius: "12px" }}>
          {error}
        </Alert>
      )}

      {/* Scan Results */}
      {scanData && (
        <BootlogScanResults
          scanData={scanData}
          onBack={handleBack}
          backLabel="Back to Dashboard"
          showBackButton={true}
        />
      )}

      {/* If no scanData yet, show Bottom Centered Back Button */}
      {!scanData && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 2, mb: 1 }}>
          <Button
            variant="contained"
            color="primary"
            startIcon={<ArrowBackIcon />}
            onClick={handleBack}
            sx={{
              borderRadius: "12px",
              px: 3.5,
              py: 1.1,
              fontWeight: 600,
              fontSize: "14px",
              textTransform: "none",
              boxShadow: "0 4px 14px rgba(37, 99, 235, 0.25)",
              "&:hover": {
                boxShadow: "0 6px 20px rgba(37, 99, 235, 0.35)",
              },
            }}
          >
            Back to Dashboard
          </Button>
        </Box>
      )}
    </Box>
  );
}

