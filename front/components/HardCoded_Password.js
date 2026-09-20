import React, { useState } from 'react';
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  InputAdornment,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Select,
  MenuItem,
  FormControl,
  Divider,
} from '@mui/material';
import KeyIcon from '@mui/icons-material/Key';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import FolderIcon from '@mui/icons-material/Folder';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import LanguageIcon from '@mui/icons-material/Language';
import LinkIcon from '@mui/icons-material/Link';
import SearchIcon from '@mui/icons-material/Search';
import SecurityIcon from '@mui/icons-material/Security';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import TerminalIcon from '@mui/icons-material/Terminal';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import RefreshIcon from '@mui/icons-material/Refresh';
import CheckIcon from '@mui/icons-material/Check';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import CloseIcon from '@mui/icons-material/Close';
import HomeIcon from '@mui/icons-material/Home';
import ClearIcon from '@mui/icons-material/Clear';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import DescriptionIcon from '@mui/icons-material/Description';
import DownloadIcon from '@mui/icons-material/Download';
import MusicNoteIcon from '@mui/icons-material/MusicNote';
import ImageIcon from '@mui/icons-material/Image';
import VideocamIcon from '@mui/icons-material/Videocam';
import ComputerIcon from '@mui/icons-material/Computer';
import FolderZipIcon from '@mui/icons-material/FolderZip';
import DeveloperBoardIcon from '@mui/icons-material/DeveloperBoard';
import ArrowBackIosNewIcon from '@mui/icons-material/ArrowBackIosNew';
import ArrowForwardIosIcon from '@mui/icons-material/ArrowForwardIos';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { useRouter } from 'next/router';

export default function HardCoded_Password({ onBack }) {
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
  const [directory, setDirectory] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  const [alertInfo, setAlertInfo] = useState(null);
  const [copied, setCopied] = useState(false);
  const [nativePickerLoading, setNativePickerLoading] = useState(false);

  // Server Directory Browser Modal States
  const [browserOpen, setBrowserOpen] = useState(false);
  const [browserLoading, setBrowserLoading] = useState(false);
  const [browserError, setBrowserError] = useState(null);
  const [browserData, setBrowserData] = useState({
    current_path: '',
    parent_path: null,
    sidebar_places: [],
    directories: [],
    files: [],
  });
  const [selectedItemPath, setSelectedItemPath] = useState('');
  const [browserFilter, setBrowserFilter] = useState('');
  const [fileTypeFilter, setFileTypeFilter] = useState('all_supported');
  const [history, setHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [modalCopied, setModalCopied] = useState(false);
  const [inputCopied, setInputCopied] = useState(false);

  const fetchDirectory = async (targetPath = null, isNavHistory = false) => {
    setBrowserLoading(true);
    setBrowserError(null);
    try {
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const params = {};
      if (targetPath) {
        params.path = targetPath;
      }
      const res = await axios.get(`${baseUrl}/browse-directory`, { params });
      if (res.data && res.data.success) {
        setBrowserData(res.data);
        setSelectedItemPath(res.data.current_path);

        const newPath = res.data.current_path;
        if (!isNavHistory) {
          setHistory((prev) => {
            const truncated = prev.slice(0, historyIndex + 1);
            if (truncated[truncated.length - 1] !== newPath) {
              const updated = [...truncated, newPath];
              setHistoryIndex(updated.length - 1);
              return updated;
            }
            return prev;
          });
        }
      }
    } catch (err) {
      console.error('Failed to browse directory:', err);
      setBrowserError(err.response?.data?.detail || err.message || 'Failed to read directory');
    } finally {
      setBrowserLoading(false);
    }
  };

  const handleNavBack = () => {
    if (historyIndex > 0) {
      const prevPath = history[historyIndex - 1];
      setHistoryIndex(historyIndex - 1);
      fetchDirectory(prevPath, true);
    }
  };

  const handleNavForward = () => {
    if (historyIndex < history.length - 1) {
      const nextPath = history[historyIndex + 1];
      setHistoryIndex(historyIndex + 1);
      fetchDirectory(nextPath, true);
    }
  };

  const handleOpenBrowser = () => {
    setBrowserOpen(true);
    setBrowserFilter('');
    fetchDirectory(directory.trim() || null);
  };

  const handleOpenNativePicker = async () => {
    try {
      setNativePickerLoading(true);
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const res = await axios.post(`${baseUrl}/pick-native-folder`, null, {
        params: { initial_dir: directory.trim() || undefined }
      });
      if (res.data && res.data.success && res.data.path) {
        setDirectory(res.data.path);
      }
    } catch (err) {
      console.error('Failed to open native picker:', err);
    } finally {
      setNativePickerLoading(false);
    }
  };

  const handleCopyPath = (path) => {
    if (!path) return;
    navigator.clipboard.writeText(path);
    setModalCopied(true);
    setTimeout(() => setModalCopied(false), 2000);
  };

  const handleSelectAndFill = (path) => {
    const finalPath = path || selectedItemPath || browserData.current_path;
    if (finalPath) {
      setDirectory(finalPath);
    }
    setBrowserOpen(false);
  };

  const copyToClipboard = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleScan = async () => {
    if (!directory.trim()) {
      setAlertInfo({ type: 'warning', message: 'Please specify an extracted firmware directory path to scan.' });
      return;
    }

    setLoading(true);
    setScanData(null);
    setAlertInfo(null);

    try {
      const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/scan-credentials`, {
        directory_path: directory.trim()
      });

      setScanData(response.data);
      setAlertInfo({
        type: 'success',
        message: `Scan finished! Discovered ${response.data.extracted_credentials?.length || 0} credentials & ${response.data.keys_and_certificates?.length || 0} keys/certs.`
      });
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Scan failed. Please verify the target path.';
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

      {/* Target Directory Configuration Card */}
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <FolderIcon color="primary" /> Extracted Firmware Directory Path
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2.5 }}>
          Specify the directory path of the extracted firmware filesystem to audit for embedded credentials, private keys, certificates, and secrets.
        </Typography>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
          <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'stretch' }}>
            <TextField
              fullWidth
              size="small"
              label="Firmware Directory Path"
              placeholder="e.g. extracted_files/_firmware.bin.extracted or target folder"
              value={directory}
              onChange={(e) => setDirectory(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              InputProps={{
                endAdornment: directory ? (
                  <InputAdornment position="end">
                    <Tooltip title="Clear path">
                      <IconButton size="small" onClick={() => setDirectory('')} edge="end" sx={{ mr: 0.5 }}>
                        <ClearIcon sx={{ fontSize: 16 }} />
                      </IconButton>
                    </Tooltip>
                  </InputAdornment>
                ) : null,
              }}
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px', bgcolor: 'background.default' } }}
            />

            <Button
              variant="outlined"
              color="primary"
              onClick={handleOpenBrowser}
              startIcon={<FolderOpenIcon />}
              sx={{
                borderRadius: '12px',
                textTransform: 'none',
                fontWeight: 600,
                px: 2.5,
                whiteSpace: 'nowrap',
              }}
            >
              Explore
            </Button>

            <Button
              variant="contained"
              color="primary"
              onClick={handleOpenNativePicker}
              disabled={nativePickerLoading}
              startIcon={nativePickerLoading ? <CircularProgress size={16} color="inherit" /> : <FolderOpenIcon />}
              sx={{
                borderRadius: '12px',
                textTransform: 'none',
                fontWeight: 600,
                px: 3,
                whiteSpace: 'nowrap',
                boxShadow: '0 2px 8px rgba(37, 99, 235, 0.2)',
              }}
            >
              {nativePickerLoading ? 'Opening...' : 'Browse'}
            </Button>
          </Box>

          {/* Main Action Button */}
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 1 }}>
            <Button
              variant="contained"
              color="primary"
              onClick={handleScan}
              disabled={loading || !directory.trim()}
              startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
              sx={{
                borderRadius: '12px',
                px: 5,
                py: 1.3,
                fontWeight: 700,
                fontSize: '15px',
                boxShadow: '0 4px 14px rgba(37, 99, 235, 0.25)',
                '&:hover': {
                  boxShadow: '0 6px 20px rgba(37, 99, 235, 0.35)',
                },
                whiteSpace: 'nowrap',
              }}
            >
              {loading ? 'Scanning Directory...' : 'Scan Directory for Secrets'}
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* Binwalk / Extraction Output Stream Terminal */}
      {scanData?.extraction_log && (
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
                {(scanData.extraction_tool || 'BINWALK').toUpperCase()} OUTPUT STREAM
              </Typography>
            </Box>

            <Tooltip title={copied ? 'Copied!' : 'Copy Output'}>
              <IconButton
                size="small"
                onClick={() => copyToClipboard(scanData.extraction_log)}
                sx={{ color: '#94A3B8', '&:hover': { color: '#FFFFFF' } }}
              >
                {copied ? <CheckCircleOutlineIcon fontSize="small" color="success" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Tooltip>
          </Box>

          {/* Terminal Content */}
          <Box
            sx={{
              p: 2.5,
              maxHeight: '450px',
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
              {scanData.extraction_log}
            </Typography>
          </Box>
        </Paper>
      )}

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

      {/* Native Desktop GTK File Upload / Explorer Modal (Matching Screenshot 1) */}
      <Dialog
        open={browserOpen}
        onClose={() => setBrowserOpen(false)}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: {
            borderRadius: '10px',
            height: '620px',
            maxHeight: '90vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.35)',
            border: '1px solid #334155',
          },
        }}
      >
        {/* Title Bar styled like Linux GTK window header in Screenshot 1 */}
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            px: 2,
            py: 0.8,
            bgcolor: '#475569',
            color: '#FFFFFF',
            borderBottom: '1px solid #334155',
            userSelect: 'none',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <FolderOpenIcon sx={{ fontSize: 17, color: '#93C5FD' }} />
            <Typography sx={{ fontWeight: 600, fontSize: '13px', letterSpacing: '0.2px' }}>
              File Upload
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography sx={{ fontSize: '11px', color: '#CBD5E1', fontFamily: 'monospace' }}>
              hardware-security
            </Typography>
            <IconButton
              size="small"
              onClick={() => setBrowserOpen(false)}
              sx={{ color: '#FFFFFF', p: 0.3, '&:hover': { bgcolor: 'rgba(255,255,255,0.2)' } }}
            >
              <CloseIcon sx={{ fontSize: 16 }} />
            </IconButton>
          </Box>
        </Box>

        {/* Main Body: Left Sidebar + Right Explorer Table */}
        <Box sx={{ display: 'flex', flex: 1, minHeight: 0, overflow: 'hidden' }}>
          {/* Left Sidebar (Places pane from Screenshot 1) */}
          <Box
            sx={{
              width: '210px',
              minWidth: '210px',
              bgcolor: '#F1F5F9',
              borderRight: '1px solid',
              borderColor: 'divider',
              display: 'flex',
              flexDirection: 'column',
              py: 1,
              px: 0.8,
              overflowY: 'auto',
            }}
          >
            <List dense disablePadding sx={{ display: 'flex', flexDirection: 'column', gap: 0.3 }}>
              {/* Default places matching Screenshot 1 */}
              {[
                { name: 'Recent', icon: <AccessTimeIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security/Hardware_Tool/extracted_files' },
                { name: 'Home', icon: <HomeIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security' },
                { name: 'Documents', icon: <DescriptionIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security/Documents' },
                { name: 'Downloads', icon: <DownloadIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security/Downloads' },
                { name: 'Music', icon: <MusicNoteIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security/Music' },
                { name: 'Pictures', icon: <ImageIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security/Pictures' },
                { name: 'Videos', icon: <VideocamIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security/Videos' },
              ].map((place) => {
                const isActive = browserData.current_path === place.path;
                return (
                  <ListItemButton
                    key={place.name}
                    dense
                    onClick={() => fetchDirectory(place.path)}
                    sx={{
                      borderRadius: '6px',
                      py: 0.6,
                      px: 1.2,
                      bgcolor: isActive ? '#94A3B8 !important' : 'transparent',
                      color: isActive ? '#FFFFFF !important' : '#334155',
                      '&:hover': { bgcolor: isActive ? '#94A3B8' : '#E2E8F0' },
                      transition: '0.1s',
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 28, color: isActive ? '#FFFFFF' : '#64748B' }}>
                      {place.icon}
                    </ListItemIcon>
                    <ListItemText
                      primary={place.name}
                      primaryTypographyProps={{
                        fontSize: '13px',
                        fontWeight: isActive ? 700 : 500,
                        color: 'inherit',
                      }}
                    />
                  </ListItemButton>
                );
              })}

              <Divider sx={{ my: 0.8 }} />

              {/* Additional project locations */}
              {[
                { name: 'extracted_files', icon: <FolderZipIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security/Hardware_Tool/extracted_files' },
                { name: 'Hardware_Tool', icon: <DeveloperBoardIcon sx={{ fontSize: 18 }} />, path: '/home/hardware-security/Hardware_Tool' },
                { name: 'Other Locations', icon: <ComputerIcon sx={{ fontSize: 18 }} />, path: '/' },
              ].map((place) => {
                const isActive = browserData.current_path === place.path;
                return (
                  <ListItemButton
                    key={place.name}
                    dense
                    onClick={() => fetchDirectory(place.path)}
                    sx={{
                      borderRadius: '6px',
                      py: 0.6,
                      px: 1.2,
                      bgcolor: isActive ? '#94A3B8 !important' : 'transparent',
                      color: isActive ? '#FFFFFF !important' : '#334155',
                      '&:hover': { bgcolor: isActive ? '#94A3B8' : '#E2E8F0' },
                      transition: '0.1s',
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 28, color: isActive ? '#FFFFFF' : '#64748B' }}>
                      {place.icon}
                    </ListItemIcon>
                    <ListItemText
                      primary={place.name}
                      primaryTypographyProps={{
                        fontSize: '13px',
                        fontWeight: isActive ? 700 : 500,
                        color: 'inherit',
                      }}
                    />
                  </ListItemButton>
                );
              })}
            </List>
          </Box>

          {/* Right Main Panel: Toolbar + Table View */}
          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, bgcolor: 'background.paper' }}>
            {/* Top Toolbar matching Screenshot 1 */}
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 1,
                px: 1.5,
                py: 0.8,
                borderBottom: '1px solid',
                borderColor: 'divider',
                bgcolor: 'background.default',
              }}
            >
              {/* Back / Forward history buttons */}
              <Box sx={{ display: 'flex', gap: 0.4 }}>
                <IconButton
                  size="small"
                  disabled={historyIndex <= 0 || browserLoading}
                  onClick={handleNavBack}
                  sx={{
                    width: 28,
                    height: 28,
                    borderRadius: '4px',
                    bgcolor: 'background.paper',
                    border: '1px solid',
                    borderColor: 'divider',
                  }}
                >
                  <ArrowBackIosNewIcon sx={{ fontSize: 11 }} />
                </IconButton>
                <IconButton
                  size="small"
                  disabled={historyIndex >= history.length - 1 || browserLoading}
                  onClick={handleNavForward}
                  sx={{
                    width: 28,
                    height: 28,
                    borderRadius: '4px',
                    bgcolor: 'background.paper',
                    border: '1px solid',
                    borderColor: 'divider',
                  }}
                >
                  <ArrowForwardIosIcon sx={{ fontSize: 11 }} />
                </IconButton>
              </Box>

              {/* Up to parent directory */}
              <IconButton
                size="small"
                disabled={!browserData.parent_path || browserLoading}
                onClick={() => browserData.parent_path && fetchDirectory(browserData.parent_path)}
                sx={{
                  width: 28,
                  height: 28,
                  borderRadius: '4px',
                  bgcolor: 'background.paper',
                  border: '1px solid',
                  borderColor: 'divider',
                }}
              >
                <ArrowUpwardIcon sx={{ fontSize: 14 }} />
              </IconButton>

              {/* Breadcrumb path bar matching Screenshot 1 (e.g. hardware-security > Downloads) */}
              <Box
                sx={{
                  flex: 1,
                  display: 'flex',
                  alignItems: 'center',
                  bgcolor: 'background.paper',
                  border: '1px solid',
                  borderColor: 'divider',
                  borderRadius: '6px',
                  height: '30px',
                  px: 1,
                  overflowX: 'auto',
                  gap: 0.4,
                }}
              >
                <Box
                  onClick={() => fetchDirectory('/home/hardware-security')}
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 0.4,
                    px: 0.8,
                    py: 0.2,
                    borderRadius: '4px',
                    cursor: 'pointer',
                    bgcolor: browserData.current_path === '/home/hardware-security' ? '#CBD5E1' : 'transparent',
                    '&:hover': { bgcolor: '#E2E8F0' },
                  }}
                >
                  <HomeIcon sx={{ fontSize: 14, color: '#475569' }} />
                  <Typography sx={{ fontSize: '12px', fontWeight: 600, color: 'text.primary' }}>
                    hardware-security
                  </Typography>
                </Box>

                {(() => {
                  const cp = browserData.current_path || '';
                  let rel = '';
                  if (cp.startsWith('/home/hardware-security')) {
                    rel = cp.slice('/home/hardware-security'.length);
                  } else {
                    rel = cp;
                  }
                  const segs = rel.split('/').filter(Boolean);
                  let buildPath = cp.startsWith('/home/hardware-security') ? '/home/hardware-security' : '';

                  return segs.map((seg, sIdx) => {
                    buildPath += '/' + seg;
                    const thisPath = buildPath;
                    const isLast = sIdx === segs.length - 1;
                    return (
                      <React.Fragment key={thisPath}>
                        <ChevronRightIcon sx={{ fontSize: 13, color: 'text.disabled' }} />
                        <Box
                          onClick={() => fetchDirectory(thisPath)}
                          sx={{
                            px: 0.8,
                            py: 0.2,
                            borderRadius: '4px',
                            cursor: 'pointer',
                            bgcolor: isLast ? '#CBD5E1' : 'transparent',
                            '&:hover': { bgcolor: '#E2E8F0' },
                          }}
                        >
                          <Typography sx={{ fontSize: '12px', fontWeight: isLast ? 700 : 500, color: 'text.primary' }}>
                            {seg}
                          </Typography>
                        </Box>
                      </React.Fragment>
                    );
                  });
                })()}
              </Box>

              {/* Search input on the right */}
              <TextField
                size="small"
                placeholder="Search..."
                value={browserFilter}
                onChange={(e) => setBrowserFilter(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ fontSize: 15, color: 'text.secondary' }} />
                    </InputAdornment>
                  ),
                  endAdornment: browserFilter ? (
                    <InputAdornment position="end">
                      <IconButton size="small" onClick={() => setBrowserFilter('')}>
                        <ClearIcon sx={{ fontSize: 13 }} />
                      </IconButton>
                    </InputAdornment>
                  ) : null,
                }}
                sx={{
                  width: '160px',
                  '& .MuiOutlinedInput-root': {
                    borderRadius: '6px',
                    fontSize: '12px',
                    height: '30px',
                    bgcolor: 'background.paper',
                  },
                }}
              />
            </Box>

            {/* Table Header & Table View matching Screenshot 1 */}
            <Box sx={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
              <Table size="small" stickyHeader sx={{ width: '100%' }}>
                <TableHead>
                  <TableRow sx={{ '& th': { bgcolor: '#F8FAFC', py: 0.6, px: 1.5, fontSize: '12px', fontWeight: 600, color: '#64748B', borderBottom: '1px solid #CBD5E1' } }}>
                    <TableCell sx={{ width: '45%' }}>Name</TableCell>
                    <TableCell sx={{ width: '18%' }}>Size</TableCell>
                    <TableCell sx={{ width: '18%' }}>Type</TableCell>
                    <TableCell sx={{ width: '19%' }}>Modified</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {browserLoading ? (
                    <TableRow>
                      <TableCell colSpan={4} align="center" sx={{ py: 6 }}>
                        <CircularProgress size={28} />
                      </TableCell>
                    </TableRow>
                  ) : (() => {
                    const allDirs = browserData.directories || [];
                    const allFiles = browserData.files || [];

                    const filteredDirs = allDirs.filter((d) => {
                      if (browserFilter && !d.name.toLowerCase().includes(browserFilter.toLowerCase())) return false;
                      return true;
                    });

                    const filteredFiles = allFiles.filter((f) => {
                      if (fileTypeFilter === 'folders_only') return false;
                      if (browserFilter && !f.name.toLowerCase().includes(browserFilter.toLowerCase())) return false;
                      if (fileTypeFilter === 'firmware_archives') {
                        return ['Binary', 'Archive'].includes(f.type);
                      }
                      return true;
                    });

                    if (filteredDirs.length === 0 && filteredFiles.length === 0) {
                      return (
                        <TableRow>
                          <TableCell colSpan={4} align="center" sx={{ py: 6, color: 'text.secondary', fontSize: '13px' }}>
                            No items found in this directory
                          </TableCell>
                        </TableRow>
                      );
                    }

                    return (
                      <>
                        {/* Subdirectories */}
                        {filteredDirs.map((dir) => {
                          const isSelected = selectedItemPath === dir.path;
                          return (
                            <TableRow
                              key={dir.path}
                              hover
                              onClick={() => setSelectedItemPath(dir.path)}
                              onDoubleClick={() => fetchDirectory(dir.path)}
                              sx={{
                                cursor: 'pointer',
                                bgcolor: isSelected ? '#475569 !important' : 'inherit',
                                '&:hover': { bgcolor: isSelected ? '#475569 !important' : '#F1F5F9' },
                                '& td': {
                                  color: isSelected ? '#FFFFFF !important' : 'inherit',
                                  py: 0.5,
                                  px: 1.5,
                                  fontSize: '12.5px',
                                  borderBottom: '1px solid #E2E8F0',
                                },
                              }}
                            >
                              <TableCell>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  <FolderIcon sx={{ fontSize: 18, color: isSelected ? '#FFFFFF' : '#3B82F6' }} />
                                  <Typography sx={{ fontSize: '12.5px', fontWeight: 600, color: 'inherit' }} noWrap>
                                    {dir.name}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell sx={{ color: isSelected ? '#E2E8F0' : '#64748B' }}>
                                {dir.formatted_size || `${dir.item_count} items`}
                              </TableCell>
                              <TableCell sx={{ color: isSelected ? '#E2E8F0' : '#64748B' }}>
                                Folder
                              </TableCell>
                              <TableCell sx={{ color: isSelected ? '#E2E8F0' : '#64748B' }}>
                                {dir.formatted_mtime || '--'}
                              </TableCell>
                            </TableRow>
                          );
                        })}

                        {/* Files */}
                        {filteredFiles.map((file) => {
                          const isSelected = selectedItemPath === file.path;
                          return (
                            <TableRow
                              key={file.path}
                              hover
                              onClick={() => setSelectedItemPath(file.path)}
                              onDoubleClick={() => handleSelectAndFill(file.path)}
                              sx={{
                                cursor: 'pointer',
                                bgcolor: isSelected ? '#475569 !important' : 'inherit',
                                '&:hover': { bgcolor: isSelected ? '#475569 !important' : '#F1F5F9' },
                                '& td': {
                                  color: isSelected ? '#FFFFFF !important' : 'inherit',
                                  py: 0.5,
                                  px: 1.5,
                                  fontSize: '12.5px',
                                  borderBottom: '1px solid #E2E8F0',
                                },
                              }}
                            >
                              <TableCell>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  {file.type === 'Archive' ? (
                                    <FolderZipIcon sx={{ fontSize: 18, color: isSelected ? '#FFFFFF' : '#F59E0B' }} />
                                  ) : file.type === 'Binary' ? (
                                    <DeveloperBoardIcon sx={{ fontSize: 18, color: isSelected ? '#FFFFFF' : '#6366F1' }} />
                                  ) : (
                                    <InsertDriveFileIcon sx={{ fontSize: 18, color: isSelected ? '#FFFFFF' : '#94A3B8' }} />
                                  )}
                                  <Typography sx={{ fontSize: '12.5px', fontWeight: 500, color: 'inherit' }} noWrap>
                                    {file.name}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell sx={{ color: isSelected ? '#E2E8F0' : '#64748B' }}>
                                {file.formatted_size}
                              </TableCell>
                              <TableCell sx={{ color: isSelected ? '#E2E8F0' : '#64748B' }}>
                                {file.type}
                              </TableCell>
                              <TableCell sx={{ color: isSelected ? '#E2E8F0' : '#64748B' }}>
                                {file.formatted_mtime}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </>
                    );
                  })()}
                </TableBody>
              </Table>
            </Box>

            {/* Bottom Controls Bar matching Screenshot 1 */}
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                px: 2,
                py: 1,
                borderTop: '1px solid',
                borderColor: 'divider',
                bgcolor: '#F8FAFC',
                gap: 2,
              }}
            >
              {/* Selected path indicator */}
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0, flex: 1 }}>
                <Typography variant="caption" sx={{ fontWeight: 700, color: '#64748B', whiteSpace: 'nowrap' }}>
                  Path:
                </Typography>
                <Box
                  sx={{
                    px: 1,
                    py: 0.3,
                    borderRadius: '4px',
                    bgcolor: 'background.paper',
                    border: '1px solid #CBD5E1',
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    color: 'text.primary',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    maxWidth: '360px',
                  }}
                >
                  {selectedItemPath || browserData.current_path || 'None'}
                </Box>
                <Tooltip title={modalCopied ? "Copied!" : "Copy selected path to clipboard"}>
                  <IconButton
                    size="small"
                    onClick={() => handleCopyPath(selectedItemPath || browserData.current_path)}
                    disabled={!selectedItemPath && !browserData.current_path}
                    sx={{ p: 0.4, border: '1px solid #CBD5E1', bgcolor: 'background.paper' }}
                  >
                    {modalCopied ? <CheckIcon sx={{ fontSize: 14, color: 'success.main' }} /> : <ContentCopyIcon sx={{ fontSize: 14 }} />}
                  </IconButton>
                </Tooltip>
              </Box>

              {/* Dropdown filter & action buttons matching Screenshot 1 */}
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <FormControl size="small" sx={{ minWidth: 160 }}>
                  <Select
                    value={fileTypeFilter}
                    onChange={(e) => setFileTypeFilter(e.target.value)}
                    sx={{ height: '30px', fontSize: '11.5px', bgcolor: 'background.paper', borderRadius: '4px' }}
                  >
                    <MenuItem value="all_supported" sx={{ fontSize: '12px' }}>All Supported Types</MenuItem>
                    <MenuItem value="folders_only" sx={{ fontSize: '12px' }}>Folders Only</MenuItem>
                    <MenuItem value="firmware_archives" sx={{ fontSize: '12px' }}>Firmware & Archives</MenuItem>
                    <MenuItem value="all_files" sx={{ fontSize: '12px' }}>All Files (*.*)</MenuItem>
                  </Select>
                </FormControl>

                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => setBrowserOpen(false)}
                  sx={{
                    borderRadius: '4px',
                    textTransform: 'none',
                    fontSize: '12px',
                    px: 2,
                    height: '30px',
                    bgcolor: '#E2E8F0',
                    color: '#334155',
                    borderColor: '#CBD5E1',
                    '&:hover': { bgcolor: '#CBD5E1' },
                  }}
                >
                  Cancel
                </Button>

                <Button
                  variant="contained"
                  size="small"
                  onClick={() => handleSelectAndFill(selectedItemPath || browserData.current_path)}
                  disabled={!selectedItemPath && !browserData.current_path}
                  sx={{
                    borderRadius: '4px',
                    textTransform: 'none',
                    fontWeight: 600,
                    fontSize: '12px',
                    px: 2.5,
                    height: '30px',
                    bgcolor: '#2563EB',
                    '&:hover': { bgcolor: '#1D4ED8' },
                  }}
                >
                  Open
                </Button>

                <Tooltip title="Launch the real native Linux GTK file chooser window (Screenshot 1)">
                  <IconButton
                    size="small"
                    onClick={handleOpenNativePicker}
                    sx={{
                      width: 30,
                      height: 30,
                      borderRadius: '4px',
                      border: '1px solid #CBD5E1',
                      bgcolor: '#FFFFFF',
                      '&:hover': { bgcolor: '#F1F5F9' },
                    }}
                  >
                    <OpenInNewIcon sx={{ fontSize: 15, color: '#475569' }} />
                  </IconButton>
                </Tooltip>
              </Box>
            </Box>
          </Box>
        </Box>
      </Dialog>
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
