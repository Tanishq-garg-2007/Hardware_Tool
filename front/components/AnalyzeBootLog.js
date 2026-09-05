import React, { useState, useEffect, useRef } from "react";
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

export default function AnalyzeBootLog() {
  const [directoryPath, setDirectoryPath] = useState("../data/bootlogs");
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // CVE Database Status & Updater State
  const [dbStatus, setDbStatus] = useState(null);
  const [dbLoading, setDbLoading] = useState(false);
  const [updateMsg, setUpdateMsg] = useState("");
  const pollIntervalRef = useRef(null);

  // Fetch CVE Database Status
  const fetchDbStatus = async () => {
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/cve-database/status`);
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
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/cve-database/update`, {
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
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
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
                Source: <strong>NIST National Vulnerability Database (NVD)</strong> • Full CVSS v2/v3/v4 &amp; EPSS
              </Typography>
            </Box>
          </Box>

          <Box sx={{ display: "flex", gap: 1.5, alignItems: "center" }}>
            <Button
              variant="contained"
              color="primary"
              size="small"
              onClick={() => handleUpdateDatabase(false)}
              disabled={isUpdating || dbLoading}
              startIcon={isUpdating ? <CircularProgress size={16} color="inherit" /> : <SyncIcon />}
              sx={{ borderRadius: "10px", fontWeight: 600 }}
            >
              {isUpdating ? "Updating..." : "Update Database"}
            </Button>
            <Button
              variant="outlined"
              size="small"
              onClick={() => handleUpdateDatabase(true)}
              disabled={isUpdating || dbLoading}
              sx={{ borderRadius: "10px", fontWeight: 600, color: "text.secondary" }}
            >
              Force Sync
            </Button>
          </Box>
        </Box>

        {/* Database Stats Row */}
        <Grid container spacing={1.5}>
          <Grid item xs={6} sm={3}>
            <Box sx={{ p: 1.5, borderRadius: "10px", backgroundColor: "background.paper", border: "1px solid", borderColor: "divider" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500, display: "block" }}>
                Database Provider
              </Typography>
              <Typography variant="body2" sx={{ fontWeight: 700, color: "text.primary" }}>
                {dbStatus?.database_type || "NIST NVD 2.0"}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Box sx={{ p: 1.5, borderRadius: "10px", backgroundColor: "background.paper", border: "1px solid", borderColor: "divider" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500, display: "block" }}>
                Total Records Loaded
              </Typography>
              <Typography variant="body2" sx={{ fontWeight: 700, color: "primary.main" }}>
                {dbStatus ? `${dbStatus.total_cves_loaded.toLocaleString()} CVEs` : "Loading..."}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Box sx={{ p: 1.5, borderRadius: "10px", backgroundColor: "background.paper", border: "1px solid", borderColor: "divider" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500, display: "block" }}>
                Last Updated
              </Typography>
              <Typography variant="body2" sx={{ fontWeight: 700, color: "text.primary" }}>
                {dbStatus?.last_updated || "Never"}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Box sx={{ p: 1.5, borderRadius: "10px", backgroundColor: "background.paper", border: "1px solid", borderColor: "divider" }}>
              <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500, display: "block" }}>
                Update Health
              </Typography>
              <Chip
                label={dbStatus?.should_update ? "Update Needed" : "Up to Date"}
                color={dbStatus?.should_update ? "warning" : "success"}
                size="small"
                sx={{ fontWeight: 700, height: "22px", fontSize: "11px", mt: 0.2 }}
              />
            </Box>
          </Grid>
        </Grid>

        {/* Real-time Update Progress Bar */}
        {isUpdating && (
          <Box sx={{ mt: 1 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" sx={{ fontWeight: 600, color: "primary.main" }}>
                {statusMessage}
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 700, color: "text.primary" }}>
                {progressPercent}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{ height: 8, borderRadius: 4, backgroundColor: "action.hover" }}
            />
          </Box>
        )}

        {updateMsg && !isUpdating && (
          <Alert severity="info" onClose={() => setUpdateMsg("")} sx={{ py: 0.5, borderRadius: "10px" }}>
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
        <Box sx={{ display: "flex", gap: 2, flexWrap: { xs: "wrap", sm: "nowrap" } }}>
          <TextField
            fullWidth
            size="small"
            placeholder="e.g. ../data/bootlogs or ../data/bootlogs/boot_log_d.txt"
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
            variant="contained"
            color="primary"
            onClick={() => handleAnalyze()}
            disabled={loading}
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

        {/* Quick presets */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
          <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500 }}>
            Quick Presets:
          </Typography>
          <Chip
            label="Sample Vulnerable Bootlog (Camera U-Boot 2019.07)"
            size="small"
            color="primary"
            onClick={() => {
              const path = "../data/bootlogs/sample_iot_camera_bootlog.txt";
              setDirectoryPath(path);
              handleAnalyze(path);
            }}
            clickable
            variant="filled"
            sx={{ borderRadius: "8px", fontSize: "12px", fontWeight: 600 }}
          />
          <Chip
            label="All Bootlogs Directory (../data/bootlogs)"
            size="small"
            onClick={() => {
              const path = "../data/bootlogs";
              setDirectoryPath(path);
              handleAnalyze(path);
            }}
            clickable
            variant="outlined"
            sx={{ borderRadius: "8px", fontSize: "12px" }}
          />
        </Box>
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ borderRadius: "12px" }}>
          {error}
        </Alert>
      )}

      {/* Scan Results */}
      {scanData && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
          {/* Summary Stat Bar */}
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={6}>
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  borderRadius: "14px",
                  backgroundColor: "background.default",
                  borderColor: "divider",
                }}
              >
                <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                  Scanned Target Path
                </Typography>
                <Typography variant="body1" sx={{ fontWeight: 600, color: "text.primary", wordBreak: "break-all" }}>
                  {scanData.scanned_directory}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} sm={6} md={6}>
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  borderRadius: "14px",
                  backgroundColor: "background.default",
                  borderColor: "divider",
                }}
              >
                <Typography variant="caption" sx={{ color: "text.secondary", textTransform: "uppercase", fontWeight: 600 }}>
                  Total Log Files Scanned
                </Typography>
                <Typography variant="h5" sx={{ fontWeight: 700, color: "primary.main" }}>
                  {scanData.total_files_scanned}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          {/* List of Files */}
          {scanData.results &&
            scanData.results.map((fileItem, index) => (
              <Paper
                key={index}
                variant="outlined"
                sx={{
                  p: { xs: 2.5, md: 3 },
                  borderRadius: "18px",
                  borderColor: "divider",
                  backgroundColor: "background.default",
                  boxShadow: "0 2px 12px rgba(0,0,0,0.02)",
                }}
              >
                {/* File Title Bar */}
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 1, mb: 2.5 }}>
                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "text.primary" }}>
                      {fileItem.filename}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace" }}>
                      {fileItem.file_path}
                    </Typography>
                  </Box>
                  <Chip
                    icon={fileItem.cve_count > 0 ? <WarningAmberIcon /> : <CheckCircleOutlineIcon />}
                    label={fileItem.cve_count > 0 ? `${fileItem.cve_count} Vulnerabilities Found` : "Zero Vulnerabilities Detected"}
                    color={fileItem.cve_count > 0 ? "error" : "success"}
                    variant={fileItem.cve_count > 0 ? "filled" : "outlined"}
                    sx={{ fontWeight: 600, borderRadius: "10px" }}
                  />
                </Box>

                {fileItem.error ? (
                  <Alert severity="warning" sx={{ borderRadius: "10px" }}>
                    Error analyzing this file: {fileItem.error}
                  </Alert>
                ) : (
                  <>
                    {/* Extracted System Metadata */}
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", textTransform: "uppercase", letterSpacing: "0.5px", mb: 1.5 }}>
                        Extracted Hardware & System Specifications
                      </Typography>

                      <Grid container spacing={1.5}>
                        <InfoGridItem label="Bootloader" value={formatVal(fileItem.device_summary?.bootloader)} />
                        <InfoGridItem label="Bootloader Version" value={formatVal(fileItem.device_summary?.bootloader_version)} />
                        <InfoGridItem label="CPU / SoC" value={formatVal(fileItem.device_summary?.cpu_soc)} />
                        <InfoGridItem label="Architecture" value={formatVal(fileItem.device_summary?.architecture)} />
                        <InfoGridItem label="Board Model" value={formatVal(fileItem.device_summary?.board_model)} />
                        <InfoGridItem label="Detected Vendor" value={formatVal(fileItem.device_summary?.vendor)} />
                        <InfoGridItem label="Linux Kernel" value={formatVal(fileItem.device_summary?.kernel_version)} />
                        <InfoGridItem label="SquashFS Version" value={formatVal(fileItem.device_summary?.squashfs_version)} />
                        <InfoGridItem label="GCC Version" value={formatVal(fileItem.device_summary?.gcc_version)} />
                        <InfoGridItem label="Crypto Algorithms" value={formatVal(fileItem.device_summary?.crypto_algos)} />
                        <InfoGridItem label="Filesystem Type" value={formatVal(fileItem.device_summary?.filesystem_type)} />
                        <InfoGridItem label="Init Drivers" value={formatVal(fileItem.device_summary?.init_drivers)} />
                      </Grid>
                    </Box>

                    <Divider sx={{ my: 2.5 }} />

                    {/* Vulnerabilities Table */}
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", textTransform: "uppercase", letterSpacing: "0.5px", mb: 1.5 }}>
                        Identified CVE Vulnerabilities ({fileItem.cve_count})
                      </Typography>

                      {fileItem.matches && fileItem.matches.length > 0 ? (
                        <TableContainer component={Paper} variant="outlined" sx={{ borderRadius: "12px", maxHeight: "400px" }}>
                          <Table size="small" stickyHeader>
                            <TableHead>
                              <TableRow>
                                <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper" }}>CVE ID</TableCell>
                                <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper" }}>Severity (CVSS)</TableCell>
                                <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper" }}>CVSS Score</TableCell>
                                <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper" }}>EPSS Threat Prob.</TableCell>
                                <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper" }}>Matched Product</TableCell>
                                <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper" }}>Description</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {fileItem.matches.map((cve, cveIdx) => {
                                const scoreVal = cve.base_score ?? cve.baseScore;
                                return (
                                <TableRow key={cveIdx} hover>
                                  <TableCell sx={{ fontWeight: 600, color: "primary.main", fontFamily: "monospace" }}>
                                    {cve.cve_id || cve.id || "-"}
                                  </TableCell>
                                  <TableCell>{getSeverityChip(cve.severity, scoreVal)}</TableCell>
                                  <TableCell sx={{ fontWeight: 700 }}>
                                    {scoreVal != null && scoreVal !== "N/A"
                                      ? (typeof scoreVal === "number" ? scoreVal.toFixed(1) : scoreVal)
                                      : (cve.severity || "-")}
                                  </TableCell>
                                  <TableCell>
                                    {cve.epss_score != null ? (
                                      <Box>
                                        <Typography
                                          variant="body2"
                                          sx={{
                                            fontWeight: 700,
                                            color: cve.epss_score >= 0.3 ? "error.main" : "text.primary",
                                          }}
                                        >
                                          {(cve.epss_score * 100).toFixed(1)}%
                                        </Typography>
                                        {cve.epss_percentile != null && (
                                          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: "10px" }}>
                                            {Math.round(cve.epss_percentile * 100)}th %tile
                                          </Typography>
                                        )}
                                      </Box>
                                    ) : (
                                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                        N/A
                                      </Typography>
                                    )}
                                  </TableCell>
                                  <TableCell sx={{ color: "text.secondary", fontSize: "13px" }}>
                                    {cve.matched_product || "-"}
                                  </TableCell>
                                  <TableCell sx={{ color: "text.secondary", fontSize: "13px", maxWidth: "340px" }}>
                                    {cve.description || "-"}
                                  </TableCell>
                                </TableRow>
                              );
                              })}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      ) : (
                        <Alert severity="success" icon={<CheckCircleOutlineIcon fontSize="inherit" />} sx={{ borderRadius: "12px" }}>
                          No matching CVE vulnerabilities detected for this bootlog file.
                        </Alert>
                      )}
                    </Box>
                  </>
                )}
              </Paper>
            ))}
        </Box>
      )}
    </Box>
  );
}

function InfoGridItem({ label, value }) {
  return (
    <Grid item xs={6} sm={4} md={3}>
      <Box
        sx={{
          backgroundColor: "background.paper",
          p: 1.5,
          borderRadius: "10px",
          border: "1px solid",
          borderColor: "divider",
          height: "100%",
        }}
      >
        <Typography variant="caption" sx={{ color: "text.secondary", fontWeight: 500, display: "block", mb: 0.5 }}>
          {label}
        </Typography>
        <Typography variant="body2" sx={{ fontWeight: 600, color: "text.primary", wordBreak: "break-word" }}>
          {value}
        </Typography>
      </Box>
    </Grid>
  );
}
