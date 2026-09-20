import React, { useState, useRef } from 'react';
import {
  Box,
  Button,
  TextField,
  Typography,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
  CircularProgress,
  Paper,
  Chip,
  Grid,
  Alert,
  Divider,
  IconButton,
  Tooltip,
} from '@mui/material';
import axios from 'axios';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import LayersIcon from '@mui/icons-material/Layers';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import TerminalIcon from '@mui/icons-material/Terminal';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import { useRouter } from 'next/router';

// Modular Sub-components & Helpers
import EntropyView from './firmware/EntropyView';
import FirmAuditReportView from './firmware/FirmAuditReportView';
import CredentialScannerView from './firmware/CredentialScannerView';
import { parseFirmAuditOutput } from './firmware/FirmwareCommon';

export default function FirmwareAnalysis({ onBack }) {
  const router = useRouter();

  const handleBack = () => {
    if (onBack) {
      onBack();
    } else if (typeof window !== 'undefined' && window.history.length > 1) {
      router.back();
    } else if (router?.query?.mode) {
      router.push(`/dashboard?mode=${router.query.mode}`);
    } else {
      router.push('/dashboard');
    }
  };

  const [selectedFile, setSelectedFile] = useState(null);
  const [output, setOutput] = useState('');
  const [script, setScript] = useState('binwalk');
  const [firmAuditOption, setFirmAuditOption] = useState('-info');
  const [blockSize, setBlockSize] = useState('');
  const [txtOutput, setTxtOutput] = useState('');
  const [htmlOutput, setHtmlOutput] = useState('');
  const [graphUrl, setGraphUrl] = useState('');
  const [pngUrl, setPngUrl] = useState('');
  const [txtUrl, setTxtUrl] = useState('');
  const [graphBaseName, setGraphBaseName] = useState('');
  const [graphFolderName, setGraphFolderName] = useState('');
  const [entropyViewMode, setEntropyViewMode] = useState('interactive');
  const [showRawStream, setShowRawStream] = useState(false);
  const [savedOutputPath, setSavedOutputPath] = useState('');
  const [savedExtractedDir, setSavedExtractedDir] = useState('');
  const [openFolderLoading, setOpenFolderLoading] = useState(false);
  const [pathCopied, setPathCopied] = useState(false);
  const [extractedDirCopied, setExtractedDirCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [alertInfo, setAlertInfo] = useState(null);
  const [copied, setCopied] = useState(false);

  // Credential Scanner State
  const [credentialDirectory, setCredentialDirectory] = useState('');
  const [credentialLoading, setCredentialLoading] = useState(false);
  const [credentialResults, setCredentialResults] = useState(null);

  // FirmAudit Deep Vulnerability Audit State
  const [firmAuditResults, setFirmAuditResults] = useState(null);

  const fileInputRef = useRef(null);

  const handleFileChange = (event) => {
    if (event.target.files && event.target.files[0]) {
      setSelectedFile(event.target.files[0]);
      setAlertInfo(null);
    }
  };

  const handleOpenFolder = async (targetPath) => {
    const pathToOpen = targetPath || savedOutputPath;
    if (!pathToOpen) return;
    try {
      setOpenFolderLoading(true);
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      await axios.post(`${baseUrl}/open-native-folder`, { path: pathToOpen });
      setAlertInfo({ type: 'info', message: `Opened native file manager at: ${pathToOpen}` });
    } catch (err) {
      console.error('Failed to open folder:', err);
      const msg = err.response?.data?.detail || err.message || 'Could not launch file manager.';
      setAlertInfo({ type: 'error', message: `Error opening folder: ${msg}` });
    } finally {
      setOpenFolderLoading(false);
    }
  };

  const handleCredentialScan = async () => {
    if (!credentialDirectory.trim()) {
      setAlertInfo({ type: 'warning', message: 'Please specify a target firmware directory to scan.' });
      return;
    }

    setCredentialLoading(true);
    setAlertInfo(null);

    try {
      const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/scan-credentials`, {
        directory_path: credentialDirectory.trim(),
      });

      setCredentialResults(response.data.results || response.data);
      setAlertInfo({ type: 'success', message: 'Credential & Artifact scan completed successfully!' });
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Credential scan failed.';
      setAlertInfo({ type: 'error', message: `Credential Scan Error: ${msg}` });
    } finally {
      setCredentialLoading(false);
    }
  };

  const handleScriptChange = (event) => {
    setScript(event.target.value);
    setOutput('');
    setTxtOutput('');
    setHtmlOutput('');
    setGraphUrl('');
    setPngUrl('');
    setTxtUrl('');
    setGraphBaseName('');
    setGraphFolderName('');
    setSavedOutputPath('');
    setFirmAuditResults(null);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!selectedFile) {
      setAlertInfo({ type: 'warning', message: 'Please select a firmware binary file first.' });
      return;
    }

    setLoading(true);
    setAlertInfo(null);

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('script', script);

    if (script === 'FirmAudit') {
      formData.append('firmAuditOption', firmAuditOption);
    }

    if (script === 'extractor') {
      formData.append('block_size', blockSize || '1024');
    }

    try {
      const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData);
      const resData = response.data || {};
      const outputPath = resData.saved_path || resData.extracted_dir || resData.entropy_dir || '';
      setSavedOutputPath(outputPath);
      setSavedExtractedDir(resData.extracted_dir || '');

      if (script === 'entropy' || script === 'extractor') {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
        setTxtOutput(resData.txt_output || '');
        setHtmlOutput(resData.html_output || '');
        setGraphUrl(resData.graph_url ? `${apiUrl}${resData.graph_url}` : '');
        setPngUrl(resData.png_url ? `${apiUrl}${resData.png_url}` : '');
        setTxtUrl(resData.txt_url ? `${apiUrl}${resData.txt_url}` : '');
        setGraphBaseName(resData.base_name || (selectedFile?.name ? selectedFile.name.replace(/\.[^/.]+$/, '') : 'firmware'));
        setGraphFolderName(resData.folder_name || '');
        setOutput('');
        setShowRawStream(false);
        setFirmAuditResults(null);
      } else if (script === 'FirmAudit' && firmAuditOption === '-info') {
        setOutput(resData.output || '');
        setTxtOutput('');
        setHtmlOutput('');
        setGraphUrl('');
        setPngUrl('');
        setTxtUrl('');
        setGraphFolderName('');
        setFirmAuditResults(null);
      } else if (script === 'FirmAudit' && firmAuditOption === 'extract') {
        const rawTxt = resData.txt_output || '';
        setTxtOutput(rawTxt);
        const parsed = resData.audit_results || parseFirmAuditOutput(rawTxt);
        setFirmAuditResults(parsed);
        const outputLines = [
          `Saved Output File (.txt):\n${resData.saved_path || resData.log_file || 'N/A'}`,
          `Extracted Files Directory:\n${resData.extracted_dir || 'N/A'}`,
        ].filter(Boolean).join('\n\n');
        setOutput(outputLines);
        setHtmlOutput('');
        setGraphUrl('');
        setPngUrl('');
        setTxtUrl('');
        setGraphFolderName('');
        if (resData.extracted_dir) {
          setCredentialDirectory(resData.extracted_dir);
        }
      } else {
        setOutput(resData.output || '');
        setTxtOutput('');
        setHtmlOutput('');
        setGraphUrl('');
        setPngUrl('');
        setTxtUrl('');
        setGraphFolderName('');
        setFirmAuditResults(null);

        if (resData.output && selectedFile?.name) {
          setCredentialDirectory(`extracted_files/_${selectedFile.name}.extracted`);
        }
      }

      setAlertInfo({ type: 'success', message: `Firmware analysis with ${script} finished successfully!` });
    } catch (error) {
      const msg = error.response?.data?.error || error.response?.data?.detail || error.message;
      setAlertInfo({ type: 'error', message: `Analysis Error: ${msg}` });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copySavedPathToClipboard = (path) => {
    if (!path) return;
    navigator.clipboard.writeText(path);
    setPathCopied(true);
    setTimeout(() => setPathCopied(false), 2000);
  };

  const copyExtractedDirToClipboard = (path) => {
    if (!path) return;
    navigator.clipboard.writeText(path);
    setExtractedDirCopied(true);
    setTimeout(() => setExtractedDirCopied(false), 2000);
  };

  return (
    <Box sx={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 1 }}>
        <Box>
          <Typography variant="h3" sx={{ fontWeight: 700, color: 'text.primary', letterSpacing: '-0.5px' }}>
            Firmware Analysis & Reverse Engineering
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
            Automated unpackers, entropy mapping, and post-extraction credential discovery.
          </Typography>
        </Box>
        <Chip
          icon={<LayersIcon sx={{ fontSize: '16px !important' }} />}
          label="Binwalk • FirmAudit • Entropy"
          color="primary"
          variant="outlined"
          sx={{ borderRadius: '10px', fontWeight: 600 }}
        />
      </Box>

      {/* Inline Feedback Alerts */}
      {alertInfo && (
        <Alert
          severity={alertInfo.type}
          onClose={() => setAlertInfo(null)}
          sx={{ borderRadius: '12px', alignItems: 'center' }}
        >
          {alertInfo.message}
        </Alert>
      )}

      {/* Firmware Upload & Analysis Form Card */}
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
          <LayersIcon color="primary" /> Select Firmware Image & Tool
        </Typography>

        <form onSubmit={handleSubmit}>
          <Grid container spacing={2.5}>
            {/* File Upload Zone */}
            <Grid item xs={12}>
              <Box
                onClick={() => fileInputRef.current?.click()}
                sx={{
                  border: '2px dashed',
                  borderColor: selectedFile ? 'primary.main' : 'divider',
                  borderRadius: '16px',
                  p: 4,
                  textAlign: 'center',
                  cursor: 'pointer',
                  backgroundColor: (theme) =>
                    selectedFile
                      ? theme.palette.mode === 'dark'
                        ? 'rgba(37, 99, 235, 0.1)'
                        : 'rgba(37, 99, 235, 0.04)'
                      : theme.palette.mode === 'dark'
                      ? 'rgba(255, 255, 255, 0.02)'
                      : 'rgba(0, 0, 0, 0.01)',
                  transition: 'all 0.2s ease-in-out',
                  '&:hover': {
                    borderColor: 'primary.main',
                    backgroundColor: (theme) =>
                      theme.palette.mode === 'dark' ? 'rgba(37, 99, 235, 0.08)' : 'rgba(37, 99, 235, 0.02)',
                  },
                }}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  style={{ display: 'none' }}
                />
                {selectedFile ? (
                  <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                    <InsertDriveFileIcon sx={{ fontSize: 44, color: 'primary.main' }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, color: 'text.primary' }}>
                      {selectedFile.name}
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Click to replace file
                    </Typography>
                  </Box>
                ) : (
                  <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                    <CloudUploadIcon sx={{ fontSize: 48, color: 'text.secondary' }} />
                    <Typography variant="body1" sx={{ fontWeight: 600, color: 'text.primary' }}>
                      Click or drag & drop target firmware binary
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      Supports .bin, .hex, .img, .rom, or raw vendor firmware dumps
                    </Typography>
                  </Box>
                )}
              </Box>
            </Grid>

            {/* Analysis Tool Selector */}
            <Grid item xs={12} sm={6} md={4}>
              <FormControl fullWidth size="small">
                <InputLabel id="tool-select-label">Analysis Tool</InputLabel>
                <Select
                  labelId="tool-select-label"
                  value={script}
                  label="Analysis Tool"
                  onChange={handleScriptChange}
                  sx={{ borderRadius: '12px' }}
                >
                  <MenuItem value="binwalk">Binwalk (Standard Extraction)</MenuItem>
                  <MenuItem value="FirmAudit">FirmAudit (Comprehensive Audit)</MenuItem>
                  <MenuItem value="entropy">Firmware Entropy Analyzer</MenuItem>
                  <MenuItem value="extractor">Extractor (Custom Block Entropy)</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            {/* FirmAudit Sub-Option */}
            {script === 'FirmAudit' && (
              <Grid item xs={12} sm={6} md={4}>
                <FormControl fullWidth size="small">
                  <InputLabel id="firmaudit-mode-label">FirmAudit Mode</InputLabel>
                  <Select
                    labelId="firmaudit-mode-label"
                    value={firmAuditOption}
                    label="FirmAudit Mode"
                    onChange={(e) => setFirmAuditOption(e.target.value)}
                    sx={{ borderRadius: '12px' }}
                  >
                    <MenuItem value="-info">Quick Architecture & Info (-info)</MenuItem>
                    <MenuItem value="extract">Extract & Deep Vulnerability Audit</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            )}

            {/* Block Size for Extractor */}
            {script === 'extractor' && (
              <Grid item xs={12} sm={6} md={4}>
                <TextField
                  fullWidth
                  size="small"
                  label="Block Size (Bytes)"
                  type="number"
                  value={blockSize}
                  onChange={(e) => setBlockSize(e.target.value)}
                  placeholder="1024"
                  sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px' } }}
                />
              </Grid>
            )}

            {/* Execute Button */}
            <Grid item xs={12} sm={6} md={4} sx={{ display: 'flex', alignItems: 'center' }}>
              <Button
                type="submit"
                variant="contained"
                color="primary"
                fullWidth
                disabled={loading || !selectedFile}
                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />}
                sx={{
                  height: '42px',
                  borderRadius: '12px',
                  fontWeight: 600,
                  boxShadow: '0 4px 14px rgba(37, 99, 235, 0.25)',
                }}
              >
                {loading ? 'Analyzing Firmware...' : 'Execute Analysis'}
              </Button>
            </Grid>
          </Grid>
        </form>
      </Paper>

      {/* Output Paths & File Manager Action Banners */}
      {(savedOutputPath || savedExtractedDir) && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {/* Primary Saved Analysis Output Banner */}
          {savedOutputPath && (
            <Paper
              variant="outlined"
              sx={{
                p: 2.5,
                borderRadius: '16px',
                backgroundColor: (theme) => (theme.palette.mode === 'dark' ? 'rgba(15, 23, 42, 0.8)' : '#F8FAFC'),
                borderColor: (theme) => (theme.palette.mode === 'dark' ? '#1E293B' : '#E2E8F0'),
                display: 'flex',
                flexDirection: { xs: 'column', md: 'row' },
                alignItems: { xs: 'flex-start', md: 'center' },
                justifyContent: 'space-between',
                gap: 2,
                boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.75, minWidth: 0, flex: 1 }}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: 44,
                    height: 44,
                    borderRadius: '12px',
                    bgcolor: 'primary.main',
                    color: 'primary.contrastText',
                    flexShrink: 0,
                    boxShadow: '0 4px 12px rgba(37, 99, 235, 0.3)',
                  }}
                >
                  <FolderOpenIcon sx={{ fontSize: 24 }} />
                </Box>
                <Box sx={{ minWidth: 0, flex: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5, flexWrap: 'wrap' }}>
                    <Typography variant="caption" sx={{ fontWeight: 700, letterSpacing: '0.5px', textTransform: 'uppercase', color: 'primary.main' }}>
                      Saved Output Location
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '11px' }}>
                      (Stored in workspace data directory)
                    </Typography>
                  </Box>
                  <Tooltip title="Click to copy path" arrow>
                    <Typography
                      onClick={() => copySavedPathToClipboard(savedOutputPath)}
                      sx={{
                        fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
                        fontSize: '13px',
                        fontWeight: 500,
                        color: 'text.primary',
                        bgcolor: (theme) => (theme.palette.mode === 'dark' ? '#0F172A' : '#FFFFFF'),
                        px: 1.5,
                        py: 0.75,
                        borderRadius: '8px',
                        border: '1px solid',
                        borderColor: (theme) => (theme.palette.mode === 'dark' ? '#334155' : '#CBD5E1'),
                        cursor: 'pointer',
                        display: 'inline-block',
                        maxWidth: '100%',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        transition: 'all 0.2s ease',
                        '&:hover': {
                          borderColor: 'primary.main',
                          bgcolor: (theme) => (theme.palette.mode === 'dark' ? '#1E293B' : '#F1F5F9'),
                        },
                      }}
                    >
                      {savedOutputPath}
                    </Typography>
                  </Tooltip>
                </Box>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2, flexShrink: 0, width: { xs: '100%', md: 'auto' }, justifyContent: { xs: 'flex-end', md: 'flex-start' } }}>
                <Tooltip title={pathCopied ? 'Copied to clipboard!' : 'Copy full path'}>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => copySavedPathToClipboard(savedOutputPath)}
                    startIcon={pathCopied ? <CheckCircleOutlineIcon color="success" /> : <ContentCopyIcon />}
                    sx={{
                      borderRadius: '10px',
                      textTransform: 'none',
                      fontWeight: 600,
                      fontSize: '12px',
                      borderColor: (theme) => (theme.palette.mode === 'dark' ? '#475569' : '#CBD5E1'),
                    }}
                  >
                    {pathCopied ? 'Copied' : 'Copy Path'}
                  </Button>
                </Tooltip>

                <Tooltip title="Open this location in native Linux File Manager (pcmanfm / xdg-open)">
                  <span>
                    <Button
                      variant="contained"
                      color="primary"
                      size="small"
                      disabled={openFolderLoading}
                      onClick={() => handleOpenFolder(savedOutputPath)}
                      startIcon={openFolderLoading ? <CircularProgress size={16} color="inherit" /> : <FolderOpenIcon />}
                      sx={{
                        borderRadius: '10px',
                        textTransform: 'none',
                        fontWeight: 600,
                        fontSize: '12px',
                        boxShadow: '0 4px 14px rgba(25, 118, 210, 0.35)',
                      }}
                    >
                      {openFolderLoading ? 'Opening...' : 'Open in File Manager'}
                    </Button>
                  </span>
                </Tooltip>
              </Box>
            </Paper>
          )}

          {/* Extracted Files Folder Banner */}
          {savedExtractedDir && savedExtractedDir !== savedOutputPath && (
            <Paper
              variant="outlined"
              sx={{
                p: 2.5,
                borderRadius: '16px',
                backgroundColor: (theme) => (theme.palette.mode === 'dark' ? 'rgba(30, 41, 59, 0.7)' : '#F8FAFC'),
                borderColor: (theme) => (theme.palette.mode === 'dark' ? '#334155' : '#E2E8F0'),
                display: 'flex',
                flexDirection: { xs: 'column', md: 'row' },
                alignItems: { xs: 'flex-start', md: 'center' },
                justifyContent: 'space-between',
                gap: 2,
                boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.75, minWidth: 0, flex: 1 }}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: 44,
                    height: 44,
                    borderRadius: '12px',
                    bgcolor: 'info.main',
                    color: 'info.contrastText',
                    flexShrink: 0,
                    boxShadow: '0 4px 12px rgba(2, 136, 209, 0.3)',
                  }}
                >
                  <FolderOpenIcon sx={{ fontSize: 24 }} />
                </Box>
                <Box sx={{ minWidth: 0, flex: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5, flexWrap: 'wrap' }}>
                    <Typography variant="caption" sx={{ fontWeight: 700, letterSpacing: '0.5px', textTransform: 'uppercase', color: 'info.main' }}>
                      Extracted Files Directory
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '11px' }}>
                      (Saved in extracted_files/ as usual)
                    </Typography>
                  </Box>
                  <Tooltip title="Click to copy path" arrow>
                    <Typography
                      onClick={() => copyExtractedDirToClipboard(savedExtractedDir)}
                      sx={{
                        fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
                        fontSize: '13px',
                        fontWeight: 500,
                        color: 'text.primary',
                        bgcolor: (theme) => (theme.palette.mode === 'dark' ? '#0F172A' : '#FFFFFF'),
                        px: 1.5,
                        py: 0.75,
                        borderRadius: '8px',
                        border: '1px solid',
                        borderColor: (theme) => (theme.palette.mode === 'dark' ? '#334155' : '#CBD5E1'),
                        cursor: 'pointer',
                        display: 'inline-block',
                        maxWidth: '100%',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        transition: 'all 0.2s ease',
                        '&:hover': {
                          borderColor: 'info.main',
                          bgcolor: (theme) => (theme.palette.mode === 'dark' ? '#1E293B' : '#F1F5F9'),
                        },
                      }}
                    >
                      {savedExtractedDir}
                    </Typography>
                  </Tooltip>
                </Box>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2, flexShrink: 0, width: { xs: '100%', md: 'auto' }, justifyContent: { xs: 'flex-end', md: 'flex-start' } }}>
                <Tooltip title={extractedDirCopied ? 'Copied to clipboard!' : 'Copy full path'}>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => copyExtractedDirToClipboard(savedExtractedDir)}
                    startIcon={extractedDirCopied ? <CheckCircleOutlineIcon color="success" /> : <ContentCopyIcon />}
                    sx={{
                      borderRadius: '10px',
                      textTransform: 'none',
                      fontWeight: 600,
                      fontSize: '12px',
                      borderColor: (theme) => (theme.palette.mode === 'dark' ? '#475569' : '#CBD5E1'),
                    }}
                  >
                    {extractedDirCopied ? 'Copied' : 'Copy Path'}
                  </Button>
                </Tooltip>

                <Tooltip title="Open this location in native Linux File Manager (pcmanfm / xdg-open)">
                  <span>
                    <Button
                      variant="contained"
                      color="info"
                      size="small"
                      disabled={openFolderLoading}
                      onClick={() => handleOpenFolder(savedExtractedDir)}
                      startIcon={openFolderLoading ? <CircularProgress size={16} color="inherit" /> : <FolderOpenIcon />}
                      sx={{
                        borderRadius: '10px',
                        textTransform: 'none',
                        fontWeight: 600,
                        fontSize: '12px',
                        boxShadow: '0 4px 14px rgba(2, 136, 209, 0.35)',
                      }}
                    >
                      {openFolderLoading ? 'Opening...' : 'Open in File Manager'}
                    </Button>
                  </span>
                </Tooltip>
              </Box>
            </Paper>
          )}
        </Box>
      )}

      {/* Modular Subcomponent: Entropy Visualization & Results */}
      {(script === 'entropy' || script === 'extractor') && Boolean(graphUrl || htmlOutput || pngUrl) && (
        <EntropyView
          graphUrl={graphUrl}
          htmlOutput={htmlOutput}
          pngUrl={pngUrl}
          txtOutput={txtOutput}
          graphFolderName={graphFolderName}
          entropyViewMode={entropyViewMode}
          setEntropyViewMode={setEntropyViewMode}
          showRawStream={showRawStream}
          setShowRawStream={setShowRawStream}
          savedOutputPath={savedOutputPath}
          openFolderLoading={openFolderLoading}
          onOpenFolder={handleOpenFolder}
          onCopy={copyToClipboard}
          copied={copied}
        />
      )}

      {/* Modular Subcomponent: Firmware Deep Vulnerability Audit Findings */}
      {script === 'FirmAudit' && firmAuditOption === 'extract' && Boolean(firmAuditResults || txtOutput) && (
        <FirmAuditReportView
          firmAuditResults={firmAuditResults}
          txtOutput={txtOutput}
          savedOutputPath={savedOutputPath}
          openFolderLoading={openFolderLoading}
          onOpenFolder={handleOpenFolder}
          onCopy={copyToClipboard}
          copied={copied}
        />
      )}

      {/* Output Terminal for Binwalk and FirmAudit (-info) */}
      {script !== 'entropy' && script !== 'extractor' && !(script === 'FirmAudit' && firmAuditOption === 'extract') && (output || txtOutput) && (
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
          {/* Terminal Title Bar */}
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
              <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: '#EF4444' }} />
              <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: '#F59E0B' }} />
              <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: '#10B981' }} />
              <Typography variant="caption" sx={{ color: '#94A3B8', fontWeight: 600, ml: 1.5 }}>
                {script.toUpperCase()} OUTPUT STREAM
              </Typography>
            </Box>

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              {savedOutputPath && (
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={openFolderLoading ? <CircularProgress size={14} color="inherit" /> : <FolderOpenIcon sx={{ fontSize: 16 }} />}
                  onClick={() => handleOpenFolder(savedOutputPath)}
                  disabled={openFolderLoading}
                  sx={{
                    color: '#38BDF8',
                    borderColor: '#1E293B',
                    fontSize: '11px',
                    textTransform: 'none',
                    fontWeight: 600,
                    py: 0.3,
                    px: 1,
                    borderRadius: '6px',
                    '&:hover': {
                      borderColor: '#38BDF8',
                      backgroundColor: 'rgba(56, 189, 248, 0.08)',
                    },
                  }}
                >
                  Open in File Manager
                </Button>
              )}

              {(output || txtOutput) && (
                <Tooltip title={copied ? 'Copied!' : 'Copy Output'}>
                  <IconButton
                    size="small"
                    onClick={() => copyToClipboard(output || txtOutput)}
                    sx={{ color: '#94A3B8', '&:hover': { color: '#FFFFFF' } }}
                  >
                    {copied ? <CheckCircleOutlineIcon fontSize="small" color="success" /> : <ContentCopyIcon fontSize="small" />}
                  </IconButton>
                </Tooltip>
              )}
            </Box>
          </Box>

          {/* Terminal Content */}
          <Box
            sx={{
              p: 2.5,
              maxHeight: '600px',
              overflowY: 'auto',
              overflowX: 'auto',
              '&::-webkit-scrollbar': {
                width: '8px',
                height: '8px',
              },
              '&::-webkit-scrollbar-track': {
                backgroundColor: '#090D16',
              },
              '&::-webkit-scrollbar-thumb': {
                backgroundColor: '#334155',
                borderRadius: '4px',
                '&:hover': {
                  backgroundColor: '#475569',
                },
              },
              scrollbarWidth: 'thin',
              scrollbarColor: '#334155 #090D16',
            }}
          >
            {output && (
              <Typography
                component="pre"
                sx={{
                  color: '#E2E8F0',
                  fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
                  fontSize: '12.5px',
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  m: 0,
                }}
              >
                {output}
              </Typography>
            )}

            {txtOutput && (
              <Typography
                component="pre"
                sx={{
                  color: '#93C5FD',
                  fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
                  fontSize: '12.5px',
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  m: 0,
                }}
              >
                {txtOutput}
              </Typography>
            )}
          </Box>
        </Paper>
      )}

      {/* Modular Subcomponent: Credential & Secret Artifact Scanner */}
      <CredentialScannerView
        credentialDirectory={credentialDirectory}
        setCredentialDirectory={setCredentialDirectory}
        credentialLoading={credentialLoading}
        handleCredentialScan={handleCredentialScan}
        credentialResults={credentialResults}
      />

      {/* Bottom Back Button */}
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4, mb: 1 }}>
        <Button
          variant="contained"
          color="primary"
          startIcon={<ArrowBackIcon />}
          onClick={handleBack}
          sx={{
            borderRadius: '12px',
            px: 3.5,
            py: 1.1,
            fontWeight: 600,
            fontSize: '14px',
            textTransform: 'none',
            backgroundColor: '#2563EB',
            backgroundImage: 'linear-gradient(135deg, #2563EB 0%, #1D4ED8 100%)',
            boxShadow: '0 4px 14px rgba(37, 99, 235, 0.25)',
            '&:hover': {
              backgroundColor: '#1D4ED8',
              backgroundImage: 'linear-gradient(135deg, #1D4ED8 0%, #1E40AF 100%)',
              boxShadow: '0 6px 20px rgba(37, 99, 235, 0.35)',
            },
          }}
        >
          Back to Tools Dashboard
        </Button>
      </Box>
    </Box>
  );
}
