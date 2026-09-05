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
  Tabs,
  Tab,
  Divider,
  IconButton,
  Tooltip
} from '@mui/material';
import axios from 'axios';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import LayersIcon from '@mui/icons-material/Layers';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import KeyIcon from '@mui/icons-material/Key';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import FolderIcon from '@mui/icons-material/Folder';
import LanguageIcon from '@mui/icons-material/Language';
import LinkIcon from '@mui/icons-material/Link';
import TerminalIcon from '@mui/icons-material/Terminal';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import SearchIcon from '@mui/icons-material/Search';

export default function FirmwareAnalysis() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [output, setOutput] = useState('');
  const [script, setScript] = useState('binwalk');
  const [firmAuditOption, setFirmAuditOption] = useState('-info');
  const [blockSize, setBlockSize] = useState('1024');
  const [txtOutput, setTxtOutput] = useState('');
  const [htmlOutput, setHtmlOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [alertInfo, setAlertInfo] = useState(null);
  const [copied, setCopied] = useState(false);

  // Credential Scanner State
  const [credentialDirectory, setCredentialDirectory] = useState('');
  const [credentialLoading, setCredentialLoading] = useState(false);
  const [credentialResults, setCredentialResults] = useState(null);
  const [activeTab, setActiveTab] = useState(0);

  const fileInputRef = useRef(null);

  // Safe extraction of Credential Scanner data
  const scanData = credentialResults || {};
  const extractedCredentials = scanData.extracted_credentials || [];
  const keysAndCertificates = scanData.keys_and_certificates || [];
  const systemFiles = scanData.system_files || [];

  const rawUrlsAndDomains = Array.isArray(scanData.urls_and_domains) ? scanData.urls_and_domains : [];
  const cleanedList = rawUrlsAndDomains
    .map((item) => (typeof item === 'string' ? item.split('\u0000')[0].trim() : ''))
    .filter(Boolean);

  const urlList = cleanedList.filter((item) => item.startsWith('http://') || item.startsWith('https://'));
  const domainList = cleanedList.filter((item) => !item.startsWith('http://') && !item.startsWith('https://'));

  const handleFileChange = (event) => {
    if (event.target.files && event.target.files[0]) {
      setSelectedFile(event.target.files[0]);
      setAlertInfo(null);
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
      formData.append('block_size', blockSize);
    }

    try {
      const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData);

      if (script === 'entropy' || script === 'extractor') {
        setTxtOutput(response.data.txt_output || '');
        setHtmlOutput(response.data.html_output || '');
        setOutput('');
      } else if (script === 'FirmAudit' && firmAuditOption === '-info') {
        setOutput(response.data.output || '');
        setTxtOutput('');
        setHtmlOutput('');
      } else if (script === 'FirmAudit' && firmAuditOption === 'extract') {
        setTxtOutput(response.data.txt_output || '');
        setOutput(`Extracted files directory:\n${response.data.extracted_dir || 'N/A'}`);
      } else {
        setOutput(response.data.output || '');
        setTxtOutput('');
        setHtmlOutput('');

        if (response.data.output && selectedFile?.name) {
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
                  backgroundColor: selectedFile ? 'action.hover' : 'background.default',
                  p: 3,
                  textAlign: 'center',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  '&:hover': { borderColor: 'primary.light', bgcolor: 'action.hover' },
                }}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  accept=".bin,.img,.rom,.elf,.hex,.tar"
                  style={{ display: 'none' }}
                />
                <CloudUploadIcon sx={{ fontSize: 36, color: selectedFile ? 'primary.main' : 'text.secondary', mb: 1 }} />
                <Typography variant="body1" sx={{ fontWeight: 600 }}>
                  {selectedFile ? selectedFile.name : 'Click to Select Firmware Binary'}
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
                  {selectedFile
                    ? `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Ready for processing`
                    : 'Accepted formats: .bin, .img, .rom, .elf, .hex, .tar'}
                </Typography>
              </Box>
            </Grid>

            {/* Tool Selection */}
            <Grid item xs={12} sm={6} md={4}>
              <FormControl fullWidth size="small">
                <InputLabel id="script-select-label">Analysis Script / Engine</InputLabel>
                <Select
                  labelId="script-select-label"
                  value={script}
                  onChange={handleScriptChange}
                  label="Analysis Script / Engine"
                  sx={{ borderRadius: '12px', bgcolor: 'background.default' }}
                >
                  <MenuItem value="binwalk">Binwalk (Extraction & Signatures)</MenuItem>
                  <MenuItem value="FirmAudit">FirmAudit (Vulnerability Scanner)</MenuItem>
                  <MenuItem value="entropy">Entropy (Full Image Graph)</MenuItem>
                  <MenuItem value="extractor">Block Entropy (Granular Chunking)</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            {/* Sub-options for FirmAudit */}
            {script === 'FirmAudit' && (
              <Grid item xs={12} sm={6} md={4}>
                <FormControl fullWidth size="small">
                  <InputLabel id="firmAudit-select-label">FirmAudit Mode</InputLabel>
                  <Select
                    labelId="firmAudit-select-label"
                    value={firmAuditOption}
                    onChange={(e) => setFirmAuditOption(e.target.value)}
                    label="FirmAudit Mode"
                    sx={{ borderRadius: '12px', bgcolor: 'background.default' }}
                  >
                    <MenuItem value="-info">Firmware Architecture & Metadata</MenuItem>
                    <MenuItem value="extract">Extract & Deep Vulnerability Audit</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            )}

            {/* Sub-options for Block Entropy */}
            {script === 'extractor' && (
              <Grid item xs={12} sm={6} md={4}>
                <TextField
                  fullWidth
                  size="small"
                  label="Block Size (Bytes)"
                  type="number"
                  value={blockSize}
                  onChange={(e) => setBlockSize(e.target.value)}
                  sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px', bgcolor: 'background.default' } }}
                />
              </Grid>
            )}

            {/* Run Button */}
            <Grid item xs={12} sm={6} md={4} sx={{ display: 'flex', alignItems: 'center' }}>
              <Button
                variant="contained"
                color="primary"
                type="submit"
                disabled={loading || !selectedFile}
                startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <PlayArrowIcon />}
                sx={{ borderRadius: '12px', py: 1, px: 3, fontWeight: 600, width: '100%' }}
              >
                {loading ? 'Analyzing Firmware...' : 'Execute Analysis'}
              </Button>
            </Grid>
          </Grid>
        </form>
      </Paper>

      {/* Output Terminal / Graph Viewer */}
      {(output || txtOutput || htmlOutput) && (
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

          {/* Terminal Content */}
          <Box sx={{ p: 2.5, maxHeight: '600px', overflowY: 'auto' }}>
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

            {htmlOutput && (
              <Box sx={{ mt: 1, borderRadius: '8px', overflow: 'hidden', bgcolor: '#FFFFFF' }}>
                <iframe
                  srcDoc={htmlOutput}
                  title="Entropy Analysis Output"
                  style={{ width: '100%', height: '520px', border: 'none' }}
                />
              </Box>
            )}
          </Box>
        </Paper>
      )}

      {/* Credential & Secret Scanner Suite */}
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
          <KeyIcon color="primary" /> Credential & Secret Artifact Scanner
        </Typography>

        <Box sx={{ display: 'flex', gap: 1.5, mb: 3 }}>
          <TextField
            fullWidth
            size="small"
            label="Extracted Firmware Directory Path"
            value={credentialDirectory}
            onChange={(e) => setCredentialDirectory(e.target.value)}
            placeholder="e.g. extracted_files/_firmware.bin.extracted or target folder"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px', bgcolor: 'background.default' } }}
          />
          <Button
            variant="contained"
            color="secondary"
            onClick={handleCredentialScan}
            disabled={credentialLoading || !credentialDirectory.trim()}
            startIcon={credentialLoading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
            sx={{ borderRadius: '12px', whiteSpace: 'nowrap', px: 3, fontWeight: 600 }}
          >
            {credentialLoading ? 'Scanning...' : 'Scan Directory'}
          </Button>
        </Box>

        {credentialResults && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
            {/* Metric Stat Cards */}
            <Grid container spacing={2}>
              <Grid item xs={6} sm={4} md={2.4}>
                <MetricCard title="Credentials" count={extractedCredentials.length} color="#EF4444" icon={<KeyIcon />} />
              </Grid>
              <Grid item xs={6} sm={4} md={2.4}>
                <MetricCard title="Keys & Certs" count={keysAndCertificates.length} color="#F59E0B" icon={<VpnKeyIcon />} />
              </Grid>
              <Grid item xs={6} sm={4} md={2.4}>
                <MetricCard title="System Files" count={systemFiles.length} color="#2563EB" icon={<FolderIcon />} />
              </Grid>
              <Grid item xs={6} sm={4} md={2.4}>
                <MetricCard title="Domains" count={domainList.length} color="#10B981" icon={<LanguageIcon />} />
              </Grid>
              <Grid item xs={6} sm={4} md={2.4}>
                <MetricCard title="Full URLs" count={urlList.length} color="#8B5CF6" icon={<LinkIcon />} />
              </Grid>
            </Grid>

            {/* Modern Tab Bar */}
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs
                value={activeTab}
                onChange={(_, v) => setActiveTab(v)}
                variant="scrollable"
                scrollButtons="auto"
                sx={{
                  '& .MuiTab-root': {
                    textTransform: 'none',
                    fontWeight: 600,
                    fontSize: '13.5px',
                    minHeight: '44px',
                  },
                }}
              >
                <Tab label={`Credentials (${extractedCredentials.length})`} />
                <Tab label={`Keys & Certs (${keysAndCertificates.length})`} />
                <Tab label={`System Files (${systemFiles.length})`} />
                <Tab label={`Domains (${domainList.length})`} />
                <Tab label={`URLs (${urlList.length})`} />
              </Tabs>
            </Box>

            {/* Tab 0: Credentials */}
            {activeTab === 0 && (
              <Box>
                {extractedCredentials.length === 0 ? (
                  <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                    No hardcoded passwords or password hashes detected.
                  </Typography>
                ) : (
                  <Box sx={{ overflowX: 'auto' }}>
                    <TableWrapper>
                      <thead>
                        <tr>
                          <th>Username</th>
                          <th>Credential / Hash</th>
                          <th>Hash Type</th>
                          <th>Source File</th>
                        </tr>
                      </thead>
                      <tbody>
                        {extractedCredentials.map((item, idx) => (
                          <tr key={idx}>
                            <td style={{ fontWeight: 700, color: '#0F172A' }}>{item.username}</td>
                            <td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{item.credential}</td>
                            <td>
                              <Chip size="small" label={item.hash_type || 'plaintext'} color="warning" sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }} />
                            </td>
                            <td style={{ fontFamily: 'monospace', fontSize: '12px', color: '#64748B' }}>{item.source_file}</td>
                          </tr>
                        ))}
                      </tbody>
                    </TableWrapper>
                  </Box>
                )}
              </Box>
            )}

            {/* Tab 1: Keys & Certs */}
            {activeTab === 1 && (
              <Box>
                {keysAndCertificates.length === 0 ? (
                  <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                    No cryptographic keys or certificates found.
                  </Typography>
                ) : (
                  <Box sx={{ overflowX: 'auto' }}>
                    <TableWrapper>
                      <thead>
                        <tr>
                          <th style={{ width: '70%' }}>File Path</th>
                          <th style={{ width: '30%' }}>Key / Cert Classification</th>
                        </tr>
                      </thead>
                      <tbody>
                        {keysAndCertificates.map((item, idx) => (
                          <tr key={idx}>
                            <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{item.file}</td>
                            <td>
                              <Chip size="small" label={item.type} color="error" variant="outlined" sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </TableWrapper>
                  </Box>
                )}
              </Box>
            )}

            {/* Tab 2: System Files */}
            {activeTab === 2 && (
              <Box>
                {systemFiles.length === 0 ? (
                  <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                    No sensitive configuration or system files identified.
                  </Typography>
                ) : (
                  <Box sx={{ overflowX: 'auto' }}>
                    <TableWrapper>
                      <thead>
                        <tr>
                          <th>Detected Sensitive System File</th>
                        </tr>
                      </thead>
                      <tbody>
                        {systemFiles.map((file, idx) => (
                          <tr key={idx}>
                            <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{file}</td>
                          </tr>
                        ))}
                      </tbody>
                    </TableWrapper>
                  </Box>
                )}
              </Box>
            )}

            {/* Tab 3: Domains */}
            {activeTab === 3 && (
              <Box>
                {domainList.length === 0 ? (
                  <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                    No domain names detected in binary data.
                  </Typography>
                ) : (
                  <Box sx={{ overflowX: 'auto' }}>
                    <TableWrapper>
                      <thead>
                        <tr>
                          <th style={{ width: '10%' }}>#</th>
                          <th style={{ width: '90%' }}>Extracted Domain Name</th>
                        </tr>
                      </thead>
                      <tbody>
                        {domainList.map((domain, idx) => (
                          <tr key={idx}>
                            <td style={{ color: '#94A3B8', fontWeight: 600 }}>{idx + 1}</td>
                            <td style={{ fontFamily: 'monospace', fontWeight: 600, color: '#047857' }}>{domain}</td>
                          </tr>
                        ))}
                      </tbody>
                    </TableWrapper>
                  </Box>
                )}
              </Box>
            )}

            {/* Tab 4: URLs */}
            {activeTab === 4 && (
              <Box>
                {urlList.length === 0 ? (
                  <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                    No HTTP/HTTPS endpoints detected.
                  </Typography>
                ) : (
                  <Box sx={{ overflowX: 'auto' }}>
                    <TableWrapper>
                      <thead>
                        <tr>
                          <th style={{ width: '10%' }}>#</th>
                          <th style={{ width: '90%' }}>Extracted Full URL</th>
                        </tr>
                      </thead>
                      <tbody>
                        {urlList.map((url, idx) => (
                          <tr key={idx}>
                            <td style={{ color: '#94A3B8', fontWeight: 600 }}>{idx + 1}</td>
                            <td style={{ fontFamily: 'monospace', wordBreak: 'break-all', color: '#2563EB' }}>{url}</td>
                          </tr>
                        ))}
                      </tbody>
                    </TableWrapper>
                  </Box>
                )}
              </Box>
            )}
          </Box>
        )}
      </Paper>
    </Box>
  );
}

function MetricCard({ title, count, color, icon }) {
  return (
    <Paper
      variant="outlined"
      sx={{
        p: 2,
        borderRadius: '14px',
        backgroundColor: 'background.default',
        border: '1px solid',
        borderColor: 'divider',
        display: 'flex',
        flexDirection: 'column',
        gap: 0.5,
      }}
    >
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color }}>
        <Typography variant="caption" sx={{ fontWeight: 700, textTransform: 'uppercase', color: 'text.secondary', letterSpacing: '0.5px' }}>
          {title}
        </Typography>
        {React.cloneElement(icon, { sx: { fontSize: 18 } })}
      </Box>
      <Typography variant="h4" sx={{ fontWeight: 800, color }}>
        {count}
      </Typography>
    </Paper>
  );
}

function TableWrapper({ children }) {
  return (
    <Box
      component="table"
      sx={{
        width: '100%',
        borderCollapse: 'collapse',
        fontSize: '13px',
        textAlign: 'left',
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: '12px',
        overflow: 'hidden',
        '& th': {
          backgroundColor: 'background.default',
          borderBottom: '2px solid',
          borderColor: 'divider',
          padding: '12px 16px',
          fontWeight: 700,
          color: 'text.primary',
        },
        '& td': {
          padding: '12px 16px',
          borderBottom: '1px solid',
          borderColor: 'divider',
          verticalAlign: 'middle',
        },
        '& tr:hover': {
          backgroundColor: 'action.hover',
        },
      }}
    >
      {children}
    </Box>
  );
}
