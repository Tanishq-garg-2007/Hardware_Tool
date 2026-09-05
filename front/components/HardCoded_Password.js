import React, { useState, useRef } from 'react';
import axios from 'axios';
import {
  Box,
  Button,
  TextField,
  Typography,
  Paper,
  CircularProgress,
  Tabs,
  Tab,
  Chip,
  Grid,
  Alert,
  IconButton,
  Tooltip,
  Collapse
} from '@mui/material';
import KeyIcon from '@mui/icons-material/Key';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import FolderIcon from '@mui/icons-material/Folder';
import LanguageIcon from '@mui/icons-material/Language';
import LinkIcon from '@mui/icons-material/Link';
import SearchIcon from '@mui/icons-material/Search';
import SecurityIcon from '@mui/icons-material/Security';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

const formatFileSize = (bytes) => {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export default function HardCoded_Password() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [directory, setDirectory] = useState('');
  const [showAdvancedPath, setShowAdvancedPath] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  const [alertInfo, setAlertInfo] = useState(null);

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
      setAlertInfo(null);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setAlertInfo(null);
    }
  };

  const handleRemoveFile = (e) => {
    e.stopPropagation();
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleScan = async () => {
    if (!selectedFile && !directory.trim()) {
      setAlertInfo({ type: 'warning', message: 'Please select a firmware file/archive to upload and scan.' });
      return;
    }

    setLoading(true);
    setScanData(null);
    setAlertInfo(null);

    try {
      let response;
      if (selectedFile) {
        const formData = new FormData();
        formData.append('file', selectedFile);
        response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/scan-credentials`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
      } else {
        response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/scan-credentials`, {
          directory_path: directory.trim()
        });
      }

      setScanData(response.data);
      setAlertInfo({
        type: 'success',
        message: `Scan finished! Discovered ${response.data.extracted_credentials?.length || 0} credentials & ${response.data.keys_and_certificates?.length || 0} keys/certs.`
      });
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Scan failed. Please verify the target file or path.';
      setAlertInfo({ type: 'error', message: msg });
    } finally {
      setLoading(false);
    }
  };

  const rawUrlsAndDomains = scanData?.urls_and_domains || [];
  const urlList = rawUrlsAndDomains.filter((item) => /^https?:\/\//i.test(item));
  const domainList = rawUrlsAndDomains.filter((item) => !/^https?:\/\//i.test(item));

  const credentials = scanData?.extracted_credentials || [];
  const keys = scanData?.keys_and_certificates || [];
  const files = scanData?.system_files || [];

  return (
    <Box sx={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 1 }}>
        <Box>
          <Typography variant="h3" sx={{ fontWeight: 700, color: 'text.primary', letterSpacing: '-0.5px' }}>
            Hardcoded Passwords & Secret Scanner
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
            Automated deep heuristic analysis for embedded credentials, private keys, certificates, and hardcoded IPs/URLs.
          </Typography>
        </Box>
        <Chip
          icon={<SecurityIcon sx={{ fontSize: '16px !important' }} />}
          label="Credential & Key Analysis"
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

      {/* Upload Target Configuration Card */}
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
          <FolderIcon color="primary" /> Target Firmware Upload
        </Typography>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
          {/* File Upload Zone */}
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
              accept=".bin,.img,.rom,.elf,.hex,.tar,.zip,.gz,.tgz,.txt,.conf,.ini,.bak,*"
              style={{ display: 'none' }}
            />

            {!selectedFile ? (
              <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                <CloudUploadIcon sx={{ fontSize: 44, color: dragActive ? 'primary.main' : 'text.secondary' }} />
                <Typography variant="body1" sx={{ fontWeight: 600, color: 'text.primary' }}>
                  {dragActive ? 'Drop firmware file or archive here' : 'Click to Browse or Drag & Drop Firmware File'}
                </Typography>
                <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                  Upload firmware binaries (.bin, .img, .rom, .elf), archives (.zip, .tar, .tar.gz), or system files (passwd, shadow, .conf)
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
                      Size: {formatFileSize(selectedFile.size)} • Ready to scan for credentials & keys
                    </Typography>
                  </Box>
                </Box>

                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Chip
                    size="small"
                    color="success"
                    label="Ready to Scan"
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

          {/* Action and Optional Path Toggle */}
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
            <Button
              variant="contained"
              color="primary"
              onClick={handleScan}
              disabled={loading || (!selectedFile && !directory.trim())}
              startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
              sx={{ borderRadius: '12px', px: 4, py: 1.2, fontWeight: 600, whiteSpace: 'nowrap' }}
            >
              {loading ? 'Scanning for Secrets...' : 'Scan Firmware for Secrets'}
            </Button>

            <Button
              variant="text"
              size="small"
              onClick={() => setShowAdvancedPath((prev) => !prev)}
              endIcon={<ExpandMoreIcon sx={{ transform: showAdvancedPath ? 'rotate(180deg)' : 'none', transition: '0.2s' }} />}
              sx={{ color: 'text.secondary', fontSize: '12px', textTransform: 'none' }}
            >
              {showAdvancedPath ? 'Hide directory path option' : 'Or specify local directory path'}
            </Button>
          </Box>

          {/* Collapsible Local Path Option for advanced/local use */}
          <Collapse in={showAdvancedPath}>
            <Box sx={{ p: 2, borderRadius: '12px', bgcolor: 'background.default', border: '1px solid', borderColor: 'divider', mt: 1 }}>
              <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
                Optional: If you already have extracted firmware directories on the local machine:
              </Typography>
              <Box sx={{ display: 'flex', gap: 1.5 }}>
                <TextField
                  fullWidth
                  size="small"
                  label="Local Server Directory Path"
                  placeholder="e.g. extracted_firm or /home/pi/extracted_firmware"
                  value={directory}
                  onChange={(e) => setDirectory(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                  sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', bgcolor: 'background.paper' } }}
                />
              </Box>
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap', mt: 1 }}>
                <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                  Presets:
                </Typography>
                <Chip
                  label="extracted_firm"
                  size="small"
                  variant="outlined"
                  onClick={() => setDirectory('extracted_firm')}
                  sx={{ borderRadius: '6px', fontSize: '11px', cursor: 'pointer' }}
                />
                <Chip
                  label="uart_logs"
                  size="small"
                  variant="outlined"
                  onClick={() => setDirectory('uart_logs')}
                  sx={{ borderRadius: '6px', fontSize: '11px', cursor: 'pointer' }}
                />
              </Box>
            </Box>
          </Collapse>
        </Box>
      </Paper>

      {/* Results Section */}
      {scanData && (
        <Paper
          variant="outlined"
          sx={{
            p: 3.5,
            borderRadius: '20px',
            backgroundColor: 'background.paper',
            boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)',
            borderColor: 'divider',
            display: 'flex',
            flexDirection: 'column',
            gap: 2.5,
          }}
        >
          {/* Summary Metric Cards */}
          <Grid container spacing={2}>
            <Grid item xs={6} sm={4} md={2.4}>
              <MetricBox title="Credentials" count={credentials.length} color="#EF4444" icon={<KeyIcon />} />
            </Grid>
            <Grid item xs={6} sm={4} md={2.4}>
              <MetricBox title="Keys & Certs" count={keys.length} color="#F59E0B" icon={<VpnKeyIcon />} />
            </Grid>
            <Grid item xs={6} sm={4} md={2.4}>
              <MetricBox title="System Files" count={files.length} color="#2563EB" icon={<FolderIcon />} />
            </Grid>
            <Grid item xs={6} sm={4} md={2.4}>
              <MetricBox title="Domains" count={domainList.length} color="#10B981" icon={<LanguageIcon />} />
            </Grid>
            <Grid item xs={6} sm={4} md={2.4}>
              <MetricBox title="Full URLs" count={urlList.length} color="#8B5CF6" icon={<LinkIcon />} />
            </Grid>
          </Grid>

          {/* Modern Tab Header */}
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
              <Tab label={`Credentials (${credentials.length})`} />
              <Tab label={`Keys & Certs (${keys.length})`} />
              <Tab label={`System Files (${files.length})`} />
              <Tab label={`Domains (${domainList.length})`} />
              <Tab label={`URLs (${urlList.length})`} />
            </Tabs>
          </Box>

          {/* Tab 0: Credentials */}
          {activeTab === 0 && (
            <Box>
              {credentials.length === 0 ? (
                <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                  No hardcoded passwords or password hashes detected.
                </Typography>
              ) : (
                <Box sx={{ overflowX: 'auto' }}>
                  <StyledTable>
                    <thead>
                      <tr>
                        <th>Username</th>
                        <th>Credential / Hash</th>
                        <th>Hash Type</th>
                        <th>Source File</th>
                      </tr>
                    </thead>
                    <tbody>
                      {credentials.map((item, idx) => (
                        <tr key={idx}>
                          <td style={{ fontWeight: 700, color: '#0F172A' }}>{item.username}</td>
                          <td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{item.credential}</td>
                          <td>
                            <Chip
                              size="small"
                              label={item.hash_type || 'plaintext'}
                              color="warning"
                              sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }}
                            />
                          </td>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px', color: '#64748B' }}>{item.source_file}</td>
                        </tr>
                      ))}
                    </tbody>
                  </StyledTable>
                </Box>
              )}
            </Box>
          )}

          {/* Tab 1: Keys & Certs */}
          {activeTab === 1 && (
            <Box>
              {keys.length === 0 ? (
                <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                  No cryptographic keys or certificates found.
                </Typography>
              ) : (
                <Box sx={{ overflowX: 'auto' }}>
                  <StyledTable>
                    <thead>
                      <tr>
                        <th style={{ width: '70%' }}>File Path</th>
                        <th style={{ width: '30%' }}>Key / Cert Classification</th>
                      </tr>
                    </thead>
                    <tbody>
                      {keys.map((item, idx) => (
                        <tr key={idx}>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{item.file}</td>
                          <td>
                            <Chip
                              size="small"
                              label={item.type}
                              color="error"
                              variant="outlined"
                              sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </StyledTable>
                </Box>
              )}
            </Box>
          )}

          {/* Tab 2: System Files */}
          {activeTab === 2 && (
            <Box>
              {files.length === 0 ? (
                <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                  No sensitive configuration or system files identified.
                </Typography>
              ) : (
                <Box sx={{ overflowX: 'auto' }}>
                  <StyledTable>
                    <thead>
                      <tr>
                        <th>Detected Sensitive System File</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map((file, idx) => (
                        <tr key={idx}>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{file}</td>
                        </tr>
                      ))}
                    </tbody>
                  </StyledTable>
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
                  <StyledTable>
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
                  </StyledTable>
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
                  <StyledTable>
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
                  </StyledTable>
                </Box>
              )}
            </Box>
          )}
        </Paper>
      )}
    </Box>
  );
}

function MetricBox({ title, count, color, icon }) {
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

function StyledTable({ children }) {
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
