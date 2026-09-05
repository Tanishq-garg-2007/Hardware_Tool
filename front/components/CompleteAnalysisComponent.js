import React, { useState, useRef } from 'react';
import {
  Box,
  Button,
  Typography,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Paper,
  CircularProgress,
  Alert,
  Chip,
  IconButton,
  Tooltip
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import DownloadIcon from '@mui/icons-material/Download';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import TaskAltIcon from '@mui/icons-material/TaskAlt';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';

const PROMPT_MAP = {
  1: { title: 'Firmware Identification', desc: 'Magic bytes, architecture signatures, vendor headers' },
  2: { title: 'Firmware Package & Artifacts', desc: 'Filesystem types, squashfs, compressed archives' },
  3: { title: 'OS & Architecture', desc: 'Kernel versions, CPU ISA (ARM, MIPS, RISC-V), glibc' },
  4: { title: 'Secure Boot Declaration', desc: 'Cryptographic signature verification, U-Boot flags' },
  5: { title: 'Network Protocols & Services', desc: 'Exposed daemons, telnet, ssh, httpd, mqtt services' },
  6: { title: 'Remote Access & Cloud', desc: 'Hardcoded endpoints, AWS/GCP IoT client hooks' },
  7: { title: 'Update & Patch Declaration', desc: 'OTA mechanisms, unauthenticated update vectors' },
  8: { title: 'Reverse Engineering Indicators', desc: 'Debug symbols, stripped binaries, anti-analysis' },
  9: { title: 'SBOM & Vulnerability', desc: 'Component inventory, CVE mapping, known exploits' }
};

const formatFileSize = (bytes) => {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const CompleteAnalysisComponent = () => {
  const [choice, setChoice] = useState('9');
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [results, setResults] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleRemoveFile = (e) => {
    e.stopPropagation();
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleAnalysis = async () => {
    if (!selectedFile) {
      setError('Please select or upload a firmware or bootlog file to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    setResults('');

    try {
      const formData = new FormData();
      formData.append('choice', choice);
      formData.append('file', selectedFile);

      const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await fetch(`${apiBase}/get_analysis/`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        let errorDetail = `Server returned HTTP ${response.status}`;
        try {
          const errJson = await response.json();
          if (errJson.detail) errorDetail = errJson.detail;
        } catch (_) {}
        throw new Error(errorDetail);
      }

      const json = await response.json();

      if (json.status === 'ok') {
        setResults(typeof json.data === 'string' ? json.data : JSON.stringify(json.data, null, 2));
      } else {
        setError(json.detail || 'Automated analysis failed.');
      }
    } catch (err) {
      setError(err.message || 'Could not connect to the backend server.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    if (!results) return;
    navigator.clipboard.writeText(results);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadReport = () => {
    if (!results) return;
    const blob = new Blob([results], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `hardware_audit_task_${choice}_${new Date().toISOString().slice(0, 10)}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Box sx={{ maxWidth: '1100px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 1 }}>
        <Box>
          <Typography variant="h3" sx={{ fontWeight: 700, color: 'text.primary', letterSpacing: '-0.5px' }}>
            Complete Security Audit
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
            Execute in-depth automated hardware & firmware security checks across nine security pillars.
          </Typography>
        </Box>
        <Chip
          icon={<SecurityIcon sx={{ fontSize: '16px !important' }} />}
          label="Multi-Pillar Auditing Engine"
          color="primary"
          variant="outlined"
          sx={{ borderRadius: '10px', fontWeight: 600 }}
        />
      </Box>

      {/* Configuration Card */}
      <Paper
        variant="outlined"
        sx={{
          p: 3.5,
          borderRadius: '20px',
          backgroundColor: 'background.paper',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)',
          borderColor: 'divider',
        }}
      >
        <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <TaskAltIcon color="primary" /> Configure Security Audit Task
        </Typography>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
          {/* Analysis Task Selector */}
          <FormControl fullWidth size="small">
            <InputLabel id="audit-task-label">Select Security Audit Task</InputLabel>
            <Select
              labelId="audit-task-label"
              value={choice}
              label="Select Security Audit Task"
              onChange={(e) => setChoice(e.target.value)}
              sx={{ borderRadius: '12px', bgcolor: 'background.default' }}
            >
              {Object.entries(PROMPT_MAP).map(([id, meta]) => (
                <MenuItem key={id} value={id}>
                  <Box sx={{ py: 0.5 }}>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {id}. {meta.title}
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
                      {meta.desc}
                    </Typography>
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Quick Preset Task Chips */}
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.8 }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', alignSelf: 'center', mr: 0.5 }}>
              Popular:
            </Typography>
            {['1', '3', '5', '8', '9'].map((id) => (
              <Chip
                key={id}
                label={PROMPT_MAP[id].title}
                size="small"
                variant={choice === id ? 'filled' : 'outlined'}
                color={choice === id ? 'primary' : 'default'}
                onClick={() => setChoice(id)}
                sx={{ borderRadius: '8px', cursor: 'pointer', fontSize: '11.5px', fontWeight: 500 }}
              />
            ))}
          </Box>

          {/* File Upload Zone */}
          <Box>
            <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.primary', mb: 1 }}>
              Target Firmware / Bootlog File
            </Typography>
            <Box
              onClick={() => fileInputRef.current?.click()}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              sx={{
                border: '2px dashed',
                borderColor: dragActive ? 'primary.main' : selectedFile ? 'success.main' : 'divider',
                borderRadius: '16px',
                backgroundColor: dragActive
                  ? 'action.hover'
                  : selectedFile
                  ? 'background.paper'
                  : 'background.default',
                p: 3,
                textAlign: 'center',
                cursor: 'pointer',
                transition: 'all 0.25s ease',
                '&:hover': { borderColor: 'primary.main', bgcolor: 'action.hover' },
              }}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                accept=".bin,.img,.rom,.elf,.hex,.tar,.zip,.gz,.txt,.log,*"
                style={{ display: 'none' }}
              />

              {!selectedFile ? (
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                  <CloudUploadIcon sx={{ fontSize: 44, color: dragActive ? 'primary.main' : 'text.secondary' }} />
                  <Typography variant="body1" sx={{ fontWeight: 600, color: 'text.primary' }}>
                    {dragActive ? 'Drop firmware file here' : 'Click to Browse or Drag & Drop Firmware File'}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    Supports raw binaries (.bin, .img, .rom, .elf), bootlogs (.txt, .log), or archives (.tar, .zip)
                  </Typography>
                </Box>
              ) : (
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, textAlign: 'left' }}>
                    <Box
                      sx={{
                        p: 1.2,
                        borderRadius: '12px',
                        bgcolor: 'primary.light',
                        color: 'primary.contrastText',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}
                    >
                      <InsertDriveFileIcon sx={{ fontSize: 28 }} />
                    </Box>
                    <Box>
                      <Typography variant="body1" sx={{ fontWeight: 700, color: 'text.primary', wordBreak: 'break-all' }}>
                        {selectedFile.name}
                      </Typography>
                      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
                        Size: {formatFileSize(selectedFile.size)} • Type: {selectedFile.type || 'Binary / Data'}
                      </Typography>
                    </Box>
                  </Box>

                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Chip
                      size="small"
                      color="success"
                      label="Ready for Audit"
                      sx={{ borderRadius: '8px', fontWeight: 600, fontSize: '11px' }}
                    />
                    <Tooltip title="Remove file">
                      <IconButton size="small" onClick={handleRemoveFile} sx={{ color: 'error.main' }}>
                        <DeleteOutlineIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </Box>
              )}
            </Box>
          </Box>

          {/* Execute Button */}
          <Button
            variant="contained"
            color="primary"
            size="large"
            onClick={handleAnalysis}
            disabled={loading || !selectedFile}
            startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />}
            sx={{ borderRadius: '12px', py: 1.2, fontWeight: 600, alignSelf: 'flex-start', px: 4 }}
          >
            {loading ? 'Executing Security Audit...' : 'Run Security Audit'}
          </Button>
        </Box>
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ borderRadius: '12px' }}>
          {error}
        </Alert>
      )}

      {/* Audit Report Terminal Window */}
      {results && (
        <Paper
          variant="outlined"
          sx={{
            borderRadius: '20px',
            backgroundColor: '#0F172A',
            border: '1px solid #1E293B',
            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.12)',
            overflow: 'hidden',
          }}
        >
          {/* Terminal Window Bar */}
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              px: 2.5,
              py: 1.5,
              borderBottom: '1px solid #1E293B',
              backgroundColor: '#090D16',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              {/* macOS Window Dots */}
              <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: '#EF4444' }} />
              <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: '#F59E0B' }} />
              <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: '#10B981' }} />
              <Typography variant="caption" sx={{ color: '#94A3B8', fontWeight: 600, ml: 1.5 }}>
                AUDIT REPORT: {PROMPT_MAP[choice]?.title.toUpperCase() || 'RESULT'}
              </Typography>
            </Box>

            <Box sx={{ display: 'flex', gap: 1 }}>
              <Tooltip title={copied ? 'Copied!' : 'Copy to Clipboard'}>
                <IconButton size="small" onClick={copyToClipboard} sx={{ color: '#94A3B8', '&:hover': { color: '#FFFFFF' } }}>
                  {copied ? <CheckCircleOutlineIcon fontSize="small" color="success" /> : <ContentCopyIcon fontSize="small" />}
                </IconButton>
              </Tooltip>
              <Tooltip title="Download Report as .txt">
                <IconButton size="small" onClick={downloadReport} sx={{ color: '#94A3B8', '&:hover': { color: '#FFFFFF' } }}>
                  <DownloadIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
          </Box>

          {/* Terminal Body */}
          <Box sx={{ p: 3, maxHeight: '550px', overflowY: 'auto' }}>
            <Typography
              component="pre"
              sx={{
                color: '#E2E8F0',
                fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
                fontSize: '13px',
                lineHeight: 1.65,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                m: 0,
              }}
            >
              {results}
            </Typography>
          </Box>
        </Paper>
      )}
    </Box>
  );
};

export default CompleteAnalysisComponent;
