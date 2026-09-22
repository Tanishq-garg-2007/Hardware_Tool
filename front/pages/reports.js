import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Grid,
  TextField,
  Typography,
  Paper,
  CircularProgress,
  Chip,
  Divider,
  Alert,
} from '@mui/material';
import Navbar from '@/components/Navbar';
import useSentenceFinder from '../hooks/useSentenceFinder';
import { useRouter } from 'next/router';
import BasicAccordion from '@/components/BasicAccordian';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import SecurityIcon from '@mui/icons-material/Security';
import HighlightIcon from '@mui/icons-material/Highlight';

const Reports = () => {
  const [keywordsToFilterString, setKeywordsToFilterString] = useState('');
  const [defaultKeywords, setDefaultKeywords] = useState(['hash', 'id', 'signature', 'gcc', 'chip', 'kernel', 'u-boot']);
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [scanError, setScanError] = useState('');
  const [hasCachedScan, setHasCachedScan] = useState(false);
  const newReport = router.query || {};

  const { sentenses, findSentences } = useSentenceFinder();

  useEffect(() => {
    try {
      const cached = sessionStorage.getItem("active_scan_data");
      if (cached) {
        const parsed = JSON.parse(cached);
        if (parsed && (parsed.results || parsed.scanned_path)) {
          setHasCachedScan(true);
        }
      }
    } catch (_) { }
  }, []);

  const handleFilterKeywords = () => {
    const filterKeywords = keywordsToFilterString.split(' ').filter((e) => e !== '');
    findSentences(newReport.report, filterKeywords);
  };

  const applyDefaultKeywords = () => {
    findSentences(newReport.report, defaultKeywords);
  };

  const analyzeBootLog = async () => {
    setLoading(true);
    setScanError('');
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const response = await fetch(`${apiBase}/cv_scan/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ boot_log: `${newReport.report || ''}` }),
      });
      const data = await response.json();
      if (data.scan_data) {
        try {
          sessionStorage.setItem("active_scan_data", JSON.stringify(data.scan_data));
          if (newReport.report) {
            sessionStorage.setItem("active_boot_log", newReport.report);
          }
        } catch (_) { }
        setHasCachedScan(true);
        // 1) Analysis results open in the new page by default
        router.push('/bootlog-report');
      } else if (data.data) {
        setScanError(data.data);
      } else {
        setScanError('Analysis failed: No scan data returned from server.');
      }
    } catch (e) {
      setScanError(`Analysis error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleBack = () => {
    if (typeof window !== 'undefined' && window.history.length > 1) {
      router.back();
    } else {
      router.push('/uart');
    }
  };

  const handleOpenReportPage = () => {
    if (hasCachedScan) {
      router.push('/bootlog-report');
    } else if (newReport.report) {
      analyzeBootLog();
    } else {
      router.push('/bootlog-report');
    }
  };

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation Header */}
      <Navbar badgeText="Boot Log Report" />

      {/* Main Content Area */}
      <Box
        sx={{
          flexGrow: 1,
          pt: { xs: 12, md: 14 },
          pb: 6,
          px: { xs: 2, md: 4 },
          maxWidth: '1600px',
          width: '100%',
          margin: '0 auto',
        }}
      >
        <Box sx={{ mb: 3 }}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={handleBack}
            sx={{
              color: 'text.secondary',
              fontWeight: 600,
              borderRadius: '10px',
              '&:hover': { color: 'text.primary', backgroundColor: 'action.hover' },
            }}
          >
            Back
          </Button>
        </Box>

        <Grid container spacing={3}>
          {/* Analysis & Quick Scan Column */}
          <Grid item xs={12} md={4}>
            <Paper
              elevation={0}
              sx={{
                p: 3,
                borderRadius: '20px',
                backgroundColor: 'background.paper',
                border: '1px solid',
                borderColor: 'divider',
                display: 'flex',
                flexDirection: 'column',
                gap: 2.5,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, color: 'text.primary', display: 'flex', alignItems: 'center', gap: 1 }}>
                <SecurityIcon color="primary" /> Vulnerability Scan
              </Typography>
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                Run pattern matchers and vulnerability databases against the captured boot session.
              </Typography>

              {/* <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Chip
                  size="small"
                  label="Active DB: NIST NVD 2.0 (390k+ CVEs)"
                  color="primary"
                  variant="outlined"
                  sx={{ fontWeight: 600, fontSize: '11px', borderRadius: '8px' }}
                />
              </Box> */}

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                <Button
                  variant="contained"
                  onClick={analyzeBootLog}
                  disabled={loading}
                  startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SecurityIcon />}
                  sx={{ borderRadius: '12px', fontWeight: 600, py: 1.1 }}
                >
                  {loading ? 'Analyzing Boot Log...' : 'Analyze Boot Log'}
                </Button>

                <Button
                  variant="outlined"
                  color="primary"
                  onClick={handleOpenReportPage}
                  disabled={loading}
                  endIcon={<ArrowForwardIcon />}
                  sx={{
                    borderRadius: '12px',
                    fontWeight: 700,
                    py: 1,
                    borderColor: 'primary.main',
                    borderWidth: '1.5px',
                    '&:hover': {
                      borderWidth: '1.5px',
                      backgroundColor: 'primary.main',
                      color: '#FFFFFF',
                    },
                  }}
                >
                  {hasCachedScan ? 'View Most Recent Report' : 'Open Full Analysis Page'}
                </Button>
              </Box>

              {/* {hasCachedScan && (
                <Chip
                  size="small"
                  label="✓ Most Recent Scan Cached"
                  color="success"
                  variant="outlined"
                  sx={{ fontWeight: 600, fontSize: '11px', borderRadius: '8px', alignSelf: 'flex-start' }}
                />
              )} */}

              {scanError && (
                <Alert severity="error" sx={{ borderRadius: '10px', fontSize: '13px' }}>
                  {scanError}
                </Alert>
              )}
            </Paper>
          </Grid>

          {/* Log Inspection & Keywords Column */}
          <Grid item xs={12} md={8}>
            <Paper
              elevation={0}
              sx={{
                p: 3,
                borderRadius: '20px',
                backgroundColor: 'background.paper',
                border: '1px solid',
                borderColor: 'divider',
                display: 'flex',
                flexDirection: 'column',
                gap: 2.5,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 700, color: 'text.primary', display: 'flex', alignItems: 'center', gap: 1 }}>
                <HighlightIcon color="primary" /> Inspect & Highlight Keywords
              </Typography>

              <Box sx={{ display: 'flex', gap: 1.5, flexWrap: { xs: 'wrap', sm: 'nowrap' } }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Enter keywords separated by spaces (e.g., hash signature uboot)"
                  value={keywordsToFilterString}
                  onChange={(e) => setKeywordsToFilterString(e.target.value)}
                  sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.default' } }}
                />
                <Button variant="contained" onClick={handleFilterKeywords} sx={{ borderRadius: '10px', fontWeight: 600, px: 3 }}>
                  Filter
                </Button>
                <Button variant="outlined" onClick={applyDefaultKeywords} sx={{ borderRadius: '10px', fontWeight: 600, px: 3 }}>
                  Defaults
                </Button>
              </Box>

              {sentenses && sentenses.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Highlighted Matches:
                  </Typography>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, maxHeight: '200px', overflowY: 'auto' }}>
                    {sentenses.map((sentence, idx) => (
                      <Box
                        key={idx}
                        sx={{
                          p: 1.5,
                          borderRadius: '8px',
                          backgroundColor: '#FEF3C7',
                          color: '#92400E',
                          fontFamily: 'monospace',
                          fontSize: '13px',
                          border: '1px solid #FDE68A',
                        }}
                      >
                        {sentence}
                      </Box>
                    ))}
                  </Box>
                </Box>
              )}

              <Divider />

              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Captured Raw Boot Log
              </Typography>

              {newReport && newReport.report ? (
                <BasicAccordion list={[{ title: 'Raw Serial Output Stream', content: newReport.report }]} />
              ) : (
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  No boot log stream passed. Please capture logs from the UART menu.
                </Typography>
              )}
            </Paper>
          </Grid>
        </Grid>

        {/* Bottom Back Button */}
        <Box sx={{ mt: 4, display: 'flex', justifyContent: 'flex-start' }}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={handleBack}
            sx={{
              color: 'text.secondary',
              fontWeight: 600,
              borderRadius: '10px',
              '&:hover': { color: 'text.primary', backgroundColor: 'action.hover' },
            }}
          >
            Back
          </Button>
        </Box>
      </Box>
    </Box>
  );
};

export default Reports;

