import React, { useEffect, useState } from "react";
import { useRouter } from "next/router";
import {
  Box,
  Typography,
  Button,
  CircularProgress,
  Alert,
  Paper,
  Chip,
} from "@mui/material";
import Navbar from "@/components/Navbar";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import RefreshIcon from "@mui/icons-material/Refresh";
import SecurityIcon from "@mui/icons-material/Security";
import BootlogScanResults from "../components/BootlogScanResults";

export default function BootlogReportPage() {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);
  const [hasLogSource, setHasLogSource] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleBack = () => {
    if (typeof window !== "undefined" && window.history.length > 1) {
      router.back();
    } else {
      router.push("/reports");
    }
  };

  useEffect(() => {
    setMounted(true);
    const forceScan = router.query.force_scan === "true" || router.query.force_scan === "1";
    const queryReport = router.query.report;
    const queryTargetPath = router.query.target_path;

    // Safely check if a boot log source is available
    let hasSource = Boolean(queryReport || queryTargetPath);
    try {
      if (!hasSource && typeof window !== "undefined" && sessionStorage.getItem("active_boot_log")) {
        hasSource = true;
      }
    } catch (_) {}
    setHasLogSource(hasSource);

    if (!forceScan) {
      // 1. Try to load scan data cached in sessionStorage
      try {
        const cached = sessionStorage.getItem("active_scan_data");
        if (cached) {
          const parsed = JSON.parse(cached);
          if (parsed && (parsed.results || parsed.scanned_path)) {
            setScanData(parsed);
            return;
          }
        }
      } catch (e) {
        console.warn("Could not read cached scan data:", e);
      }
    }

    // 2. If raw report query string is present and no cached scanData, auto-scan it
    if (queryReport) {
      runDirectScan(queryReport);
    } else if (queryTargetPath) {
      runPathScan(queryTargetPath);
    }
  }, [router.query]);

  const runDirectScan = async (bootlogContent) => {
    setLoading(true);
    setError("");
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const response = await fetch(`${apiBase}/cv_scan/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ boot_log: bootlogContent }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || data.data || "Failed to analyze boot log.");
      }

      if (data.scan_data) {
        setScanData(data.scan_data);
        sessionStorage.setItem("active_scan_data", JSON.stringify(data.scan_data));
      } else {
        throw new Error("Invalid scan result structure returned by backend.");
      }
    } catch (err) {
      setError(err.message || "Failed to scan boot log.");
    } finally {
      setLoading(false);
    }
  };

  const runPathScan = async (targetPath) => {
    setLoading(true);
    setError("");
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const response = await fetch(`${apiBase}/scan-path`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_path: targetPath, force_db_update: false }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to analyze boot log from path.");
      }

      if (data.data) {
        setScanData(data.data);
        sessionStorage.setItem("active_scan_data", JSON.stringify(data.data));
      }
    } catch (err) {
      setError(err.message || "Failed to scan boot log.");
    } finally {
      setLoading(false);
    }
  };

  const handleRescan = () => {
    const rawLog = router.query.report || (typeof window !== "undefined" ? sessionStorage.getItem("active_boot_log") : null);
    if (rawLog) {
      runDirectScan(rawLog);
    } else if (router.query.target_path) {
      runPathScan(router.query.target_path);
    }
  };

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "background.default", display: "flex", flexDirection: "column" }}>
      {/* ── Top Navigation Bar ── */}
      <Navbar badgeText="Boot Log Analysis Report" />

      {/* ── Main Content Container ── */}
      <Box
        sx={{
          flexGrow: 1,
          pt: { xs: 12, md: 14 },
          pb: 6,
          px: { xs: 2, md: 4 },
          maxWidth: "1600px",
          width: "100%",
          margin: "0 auto",
        }}
      >
        {/* Navigation & Header */}
        <Box sx={{ mb: 3, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 1.5 }}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={handleBack}
            sx={{
              color: "text.secondary",
              fontWeight: 600,
              borderRadius: "10px",
              "&:hover": { color: "text.primary", backgroundColor: "action.hover" },
            }}
          >
            Back to Reports
          </Button>

          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
            {mounted && hasLogSource && (
              <Button
                variant="outlined"
                size="small"
                onClick={handleRescan}
                disabled={loading}
                startIcon={loading ? <CircularProgress size={14} color="inherit" /> : <RefreshIcon />}
                sx={{ borderRadius: "10px", fontWeight: 600, textTransform: "none" }}
              >
                {loading ? "Re-analyzing..." : "Re-run Analysis"}
              </Button>
            )}
          </Box>
        </Box>

        {/* Loading / Mounting State */}
        {(!mounted || loading) && (
          <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", py: 12, gap: 2 }}>
            <CircularProgress size={48} thickness={4} />
            <Typography variant="h6" sx={{ fontWeight: 600, color: "text.primary" }}>
              {loading ? "Analyzing Boot Log Security Signatures..." : "Loading Boot Log Analysis Report..."}
            </Typography>
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
              {loading
                ? "Correlating extracted firmware versions against 390k+ NIST NVD 2.0 CVE records and EPSS scores."
                : "Retrieving vulnerability findings and hardware specifications."}
            </Typography>
          </Box>
        )}

        {/* Error Alert */}
        {mounted && !loading && error && (
          <Alert severity="error" sx={{ borderRadius: "12px", mb: 3 }}>
            {error}
          </Alert>
        )}

        {/* No Data State */}
        {mounted && !loading && !scanData && !error && (
          <Paper
            variant="outlined"
            sx={{
              p: 6,
              textAlign: "center",
              borderRadius: "18px",
              backgroundColor: "background.default",
              borderColor: "divider",
            }}
          >
            <SecurityIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
              No Active Boot Log Scan Available
            </Typography>
            <Typography variant="body2" sx={{ color: "text.secondary", mb: 3, maxWidth: 500, mx: "auto" }}>
              Please analyze a boot log from the Reports page or upload a boot log file to view deep vulnerability insights.
            </Typography>
            <Button
              variant="contained"
              onClick={() => router.push("/reports")}
              sx={{ borderRadius: "12px", px: 3, fontWeight: 600 }}
            >
              Go to Reports
            </Button>
          </Paper>
        )}

        {/* ── Scan Results View (Matches Screenshots 1-3) ── */}
        {mounted && !loading && scanData && (
          <BootlogScanResults
            scanData={scanData}
            onBack={handleBack}
            backLabel="Back to Reports"
            showBackButton={true}
          />
        )}
      </Box>
    </Box>
  );
}
