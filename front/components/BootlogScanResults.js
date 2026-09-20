import React from "react";
import {
  Box,
  Typography,
  Paper,
  Chip,
  Grid,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Divider,
  Button,
  Tooltip,
  Link,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";

export default function BootlogScanResults({
  scanData,
  onBack,
  backLabel = "Back to Dashboard",
  showBackButton = true,
}) {
  if (!scanData) return null;

  const formatVal = (val) => {
    if (val === undefined || val === null || val === "" || val === "N/A") return "N/A";
    if (Array.isArray(val)) return val.length > 0 ? val.join(", ") : "N/A";
    return String(val);
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

  return (
    <Box sx={{ width: "100%", display: "flex", flexDirection: "column", gap: 3 }}>
      {/* ── Summary Stat Bar ── */}
      <Grid container spacing={2}>
        <Grid item xs={12} sm={8} md={8}>
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
              {scanData.scanned_directory || scanData.scanned_path || "Live Serial Boot Stream"}
            </Typography>
          </Paper>
        </Grid>

        <Grid item xs={12} sm={4} md={4}>
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
              {scanData.total_files_scanned || (scanData.results ? scanData.results.length : 1)}
            </Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* ── List of Scanned Files / Results ── */}
      {scanData.results &&
        scanData.results.map((fileItem, index) => {
          const summary = fileItem.device_summary || {};
          const cveCount = fileItem.cve_count !== undefined ? fileItem.cve_count : (fileItem.matches ? fileItem.matches.length : 0);

          return (
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
                    {fileItem.filename || "captured_bootlog.txt"}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", fontFamily: "monospace" }}>
                    {fileItem.file_path || "Direct Serial Stream Buffer"}
                  </Typography>
                </Box>
                <Chip
                  icon={cveCount > 0 ? <WarningAmberIcon /> : <CheckCircleOutlineIcon />}
                  label={cveCount > 0 ? `${cveCount} Vulnerabilities Found` : "Zero Vulnerabilities Detected"}
                  color={cveCount > 0 ? "error" : "success"}
                  variant={cveCount > 0 ? "filled" : "outlined"}
                  sx={{
                    fontWeight: 700,
                    borderRadius: "10px",
                    px: 1,
                    py: 2.2,
                    fontSize: "13px",
                    ...(cveCount > 0
                      ? { backgroundColor: "#DC2626", color: "#FFFFFF" }
                      : {}),
                  }}
                />
              </Box>

              {fileItem.error ? (
                <Alert severity="warning" sx={{ borderRadius: "10px" }}>
                  Error analyzing this file: {fileItem.error}
                </Alert>
              ) : (
                <>
                  {/* ── Extracted Hardware & System Specifications (12 Grid Items) ── */}
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", textTransform: "uppercase", letterSpacing: "0.5px", mb: 1.5 }}>
                      Extracted Hardware & System Specifications
                    </Typography>

                    <Grid container spacing={1.5}>
                      <InfoGridItem
                        label="Bootloader"
                        value={formatVal(summary.bootloader || summary.bootloader_full_string)}
                      />
                      <InfoGridItem
                        label="Bootloader Version"
                        value={formatVal(summary.bootloader_version)}
                      />
                      <InfoGridItem
                        label="CPU / SoC"
                        value={formatVal(summary.cpu_soc || summary.cpu_raw)}
                      />
                      <InfoGridItem
                        label="Architecture"
                        value={formatVal(summary.architecture || summary.cpu_architecture)}
                      />
                      <InfoGridItem
                        label="Board Model"
                        value={formatVal(summary.board_model || summary.model_raw)}
                      />
                      <InfoGridItem
                        label="Detected Vendor"
                        value={formatVal(summary.vendor || summary.detected_vendors)}
                      />
                      <InfoGridItem
                        label="Linux Kernel"
                        value={formatVal(summary.kernel_version)}
                      />
                      <InfoGridItem
                        label="SquashFS Version"
                        value={formatVal(summary.squashfs_version)}
                      />
                      <InfoGridItem
                        label="GCC Version"
                        value={formatVal(summary.gcc_version)}
                      />
                      <InfoGridItem
                        label="Crypto Algorithms"
                        value={formatVal(summary.crypto_algos)}
                      />
                      <InfoGridItem
                        label="Filesystem Type"
                        value={formatVal(summary.filesystem_type || summary.filesystems)}
                      />
                      <InfoGridItem
                        label="Init Drivers"
                        value={formatVal(summary.init_drivers || summary.initialized_drivers)}
                      />
                    </Grid>
                  </Box>

                  <Divider sx={{ my: 2.5 }} />

                  {/* ── Identified CVE Vulnerabilities Table ── */}
                  <Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", textTransform: "uppercase", letterSpacing: "0.5px", mb: 1.5 }}>
                      Identified CVE Vulnerabilities ({cveCount})
                    </Typography>

                    {fileItem.matches && fileItem.matches.length > 0 ? (
                      <TableContainer
                        component={Paper}
                        variant="outlined"
                        sx={{
                          borderRadius: "12px",
                          maxHeight: "520px",
                          overflowX: "auto",
                          borderColor: "divider",
                        }}
                      >
                        <Table size="small" stickyHeader>
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper", minWidth: "150px" }}>CVE ID</TableCell>
                              <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper", minWidth: "120px" }}>Severity (CVSS)</TableCell>
                              <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper", minWidth: "100px" }}>CVSS Score</TableCell>
                              <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper", minWidth: "130px" }}>EPSS Threat Prob.</TableCell>
                              <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper", minWidth: "130px" }}>Matched Product</TableCell>
                              <TableCell sx={{ fontWeight: 700, backgroundColor: "background.paper", minWidth: "280px" }}>Description</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {fileItem.matches.map((cve, cveIdx) => {
                              const scoreVal = cve.base_score ?? cve.baseScore;
                              const cveId = cve.cve_id || cve.id || "-";
                              const nvdUrl = cveId.startsWith("CVE-")
                                ? `https://nvd.nist.gov/vuln/detail/${cveId}`
                                : null;

                              return (
                                <TableRow key={cveIdx} hover>
                                  <TableCell sx={{ fontWeight: 600, fontFamily: "monospace" }}>
                                    {nvdUrl ? (
                                      <Tooltip title={`Open ${cveId} advisory on NIST NVD`} arrow>
                                        <Link
                                          href={nvdUrl}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          underline="hover"
                                          sx={{
                                            color: "primary.main",
                                            display: "inline-flex",
                                            alignItems: "center",
                                            gap: 0.5,
                                            fontWeight: 700,
                                          }}
                                        >
                                          {cveId}
                                          <OpenInNewIcon sx={{ fontSize: "13px" }} />
                                        </Link>
                                      </Tooltip>
                                    ) : (
                                      cveId
                                    )}
                                  </TableCell>

                                  <TableCell>{getSeverityChip(cve.severity, scoreVal)}</TableCell>

                                  <TableCell sx={{ fontWeight: 700 }}>
                                    {scoreVal != null && scoreVal !== "N/A"
                                      ? typeof scoreVal === "number"
                                        ? scoreVal.toFixed(1)
                                        : scoreVal
                                      : cve.severity || "-"}
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
                                          <Typography variant="caption" sx={{ color: "text.secondary", fontSize: "10px", display: "block" }}>
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

                                  <TableCell sx={{ color: "text.secondary", fontSize: "13px" }}>
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
          );
        })}

      {/* ── Bottom Centered Primary Back Button ── */}
      {showBackButton && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 2, mb: 1 }}>
          <Button
            variant="contained"
            color="primary"
            startIcon={<ArrowBackIcon />}
            onClick={onBack}
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
            {backLabel}
          </Button>
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
