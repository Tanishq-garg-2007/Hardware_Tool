import React, { useEffect, useRef, useState } from 'react';
import {
  Box,
  Button,
  Grid,
  TextField,
  Typography,
  Paper,
  AppBar,
  Toolbar,
  Avatar,
  CircularProgress,
  Chip,
  Divider,
} from '@mui/material';
import useSentenceFinder from '../hooks/useSentenceFinder';
import { useRouter } from 'next/router';
import BasicAccordion from '@/components/BasicAccordian';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import SecurityIcon from '@mui/icons-material/Security';
import HighlightIcon from '@mui/icons-material/Highlight';

const Reports = () => {
  const [keywordsToFilterString, setKeywordsToFilterString] = useState('');
  const [defaultKeywords, setDefaultKeywords] = useState(['hash', 'id', 'signature', 'gcc', 'chip', 'kernel', 'u-boot']);
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [cvOutput, setCvOutput] = useState('Click "Analyze Boot Log" to extract security insights.');
  const newReport = router.query || {};

  const { sentenses, findSentences } = useSentenceFinder();

  const handleFilterKeywords = () => {
    const filterKeywords = keywordsToFilterString.split(' ').filter((e) => e !== '');
    findSentences(newReport.report, filterKeywords);
  };

  const applyDefaultKeywords = () => {
    findSentences(newReport.report, defaultKeywords);
  };

  const analyzeBootLog = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/cv_scan/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ boot_log: `${newReport.report || ''}` }),
      });
      const data = await response.json();
      setCvOutput(`${data.data || 'Analysis complete. No vulnerabilities reported.'}`);
    } catch (e) {
      setCvOutput(`Analysis error: ${e.message}`);
    }
    setLoading(false);
  };

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation Header */}
      <AppBar
        position="fixed"
        sx={{
          background: 'rgba(255, 255, 255, 0.8)',
          boxShadow: '0 4px 30px rgba(0, 0, 0, 0.03)',
          backdropFilter: 'blur(16px)',
          WebkitBackdropFilter: 'blur(16px)',
          borderBottom: '1px solid',
          borderColor: 'divider',
          width: '100%',
          color: 'text.primary',
          zIndex: 1100,
        }}
      >
        <Toolbar sx={{ padding: '8px 24px' }}>
          <Avatar
            src="https://ece.iiita.ac.in/img/logo.png"
            alt="IIIT A"
            sx={{ width: '50px', height: '50px', marginRight: '16px', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)' }}
          />
          <Typography variant="h3" component="div" sx={{ flexGrow: 1, fontSize: '1.15rem', letterSpacing: '-0.5px' }}>
            IoT Security Research Lab, IIIT Allahabad
          </Typography>

          <Typography
            variant="body2"
            component="div"
            sx={{
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: '20px',
              padding: '6px 16px',
              backgroundColor: 'background.paper',
              fontWeight: 600,
              color: 'primary.main',
              mr: 2,
            }}
          >
            Boot Log Report
          </Typography>

          <Avatar
            src="https://pbs.twimg.com/profile_images/1805473337403228160/dloBXOi-_400x400.jpg"
            alt="C3i"
            sx={{ width: '50px', height: '50px', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)' }}
          />
        </Toolbar>
      </AppBar>

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
            onClick={() => router.back()}
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

              <Button
                variant="contained"
                onClick={analyzeBootLog}
                disabled={loading}
                startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SecurityIcon />}
                sx={{ borderRadius: '12px', fontWeight: 600, py: 1 }}
              >
                {loading ? 'Analyzing...' : 'Analyze Boot Log'}
              </Button>

              <Divider />

              <Typography variant="subtitle2" sx={{ fontWeight: 600, color: 'text.primary' }}>
                Analysis Result:
              </Typography>

              <Box
                sx={{
                  p: 2,
                  borderRadius: '12px',
                  backgroundColor: 'background.default',
                  border: '1px solid',
                  borderColor: 'divider',
                  maxHeight: '350px',
                  overflowY: 'auto',
                }}
              >
                <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace', color: 'text.secondary' }}>
                  {cvOutput}
                </Typography>
              </Box>
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
      </Box>
    </Box>
  );
};

export default Reports;
