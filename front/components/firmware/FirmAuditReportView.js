import React, { useState } from 'react';
import {
  Box,
  Button,
  Typography,
  CircularProgress,
  Paper,
  Chip,
  Grid,
  Tabs,
  Tab,
  IconButton,
  Tooltip,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import BugReportIcon from '@mui/icons-material/BugReport';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import KeyIcon from '@mui/icons-material/Key';
import FolderIcon from '@mui/icons-material/Folder';
import LanguageIcon from '@mui/icons-material/Language';
import DnsIcon from '@mui/icons-material/Dns';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import TerminalIcon from '@mui/icons-material/Terminal';
import { MetricCard, TableWrapper, parseFirmAuditOutput } from './FirmwareCommon';

export default function FirmAuditReportView({
  firmAuditResults,
  txtOutput,
  savedOutputPath,
  openFolderLoading,
  onOpenFolder,
  onCopy,
  copied,
}) {
  const [activeTab, setActiveTab] = useState(0);
  const [showRawStream, setShowRawStream] = useState(false);

  const auditData = firmAuditResults || parseFirmAuditOutput(txtOutput);
  const vulns = auditData.vulnerabilities || [];
  const crypto = auditData.weak_crypto || [];
  const creds = auditData.credentials || [];
  const configs = auditData.configs_and_dbs || [];
  const endpoints = auditData.network_endpoints || [];
  const sharedLibs = auditData.shared_libraries || [];

  return (
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
      {/* Title Bar */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 1.5,
          mb: 2.5,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 44,
              height: 44,
              borderRadius: '12px',
              bgcolor: 'error.main',
              color: '#ffffff',
              boxShadow: '0 4px 14px rgba(239, 68, 68, 0.35)',
              flexShrink: 0,
            }}
          >
            <SecurityIcon sx={{ fontSize: 24 }} />
          </Box>
          <Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, lineHeight: 1.2 }}>
                Deep Vulnerability & Security Audit Findings
              </Typography>
              {vulns.length > 0 && (
                <Chip
                  size="small"
                  color="error"
                  label={`${vulns.length} High-Risk Alert${vulns.length > 1 ? 's' : ''}`}
                  sx={{ height: 22, fontSize: '11px', fontWeight: 700 }}
                />
              )}
            </Box>
            <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.3, fontSize: '12.5px' }}>
              Categorized security triage: command injections, weak cryptography, default credentials, and system artifacts.
            </Typography>
          </Box>
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          {savedOutputPath && onOpenFolder && (
            <Button
              size="small"
              variant="outlined"
              startIcon={openFolderLoading ? <CircularProgress size={13} color="inherit" /> : <FolderOpenIcon sx={{ fontSize: 16 }} />}
              onClick={() => onOpenFolder(savedOutputPath)}
              disabled={openFolderLoading}
              sx={{ borderRadius: '10px', textTransform: 'none', fontWeight: 600, fontSize: '12px', height: 32 }}
            >
              Open in File Manager
            </Button>
          )}
          <Tooltip title={copied ? 'Copied to clipboard!' : 'Copy Raw Audit Log'}>
            <Button
              size="small"
              variant="outlined"
              startIcon={copied ? <CheckCircleOutlineIcon color="success" sx={{ fontSize: 16 }} /> : <ContentCopyIcon sx={{ fontSize: 15 }} />}
              onClick={() => onCopy(txtOutput)}
              sx={{ borderRadius: '10px', textTransform: 'none', fontWeight: 600, fontSize: '12px', height: 32 }}
            >
              {copied ? 'Copied Log' : 'Copy Log'}
            </Button>
          </Tooltip>
        </Box>
      </Box>

      {/* Metric Stat Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={6} sm={4} md={2}>
          <MetricCard title="Vulnerabilities" count={vulns.length} color="#EF4444" icon={<BugReportIcon />} />
        </Grid>
        <Grid item xs={6} sm={4} md={2}>
          <MetricCard title="Weak Crypto" count={crypto.length} color="#F59E0B" icon={<LockOpenIcon />} />
        </Grid>
        <Grid item xs={6} sm={4} md={2}>
          <MetricCard title="Default Creds" count={creds.length} color="#DC2626" icon={<KeyIcon />} />
        </Grid>
        <Grid item xs={6} sm={4} md={2}>
          <MetricCard title="Configs & DBs" count={configs.length} color="#2563EB" icon={<FolderIcon />} />
        </Grid>
        <Grid item xs={6} sm={4} md={2}>
          <MetricCard title="Endpoints" count={endpoints.length} color="#10B981" icon={<LanguageIcon />} />
        </Grid>
        <Grid item xs={6} sm={4} md={2}>
          <MetricCard title="Shared Libs" count={sharedLibs.length} color="#8B5CF6" icon={<DnsIcon />} />
        </Grid>
      </Grid>

      {/* Modern Tab Bar */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2.5 }}>
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
          <Tab label={`Vulnerabilities (${vulns.length})`} />
          <Tab label={`Weak Crypto (${crypto.length})`} />
          <Tab label={`Default Credentials (${creds.length})`} />
          <Tab label={`Configs & DBs (${configs.length})`} />
          <Tab label={`Network Endpoints (${endpoints.length})`} />
          <Tab label={`Shared Libraries (${sharedLibs.length})`} />
        </Tabs>
      </Box>

      {/* Tab 0: Vulnerabilities */}
      {activeTab === 0 && (
        <Box>
          {vulns.length === 0 ? (
            <Box sx={{ py: 3, textAlign: 'center' }}>
              <CheckCircleOutlineIcon sx={{ fontSize: 36, color: 'success.main', mb: 1 }} />
              <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 500 }}>
                No critical command injection patterns or dangerous memory API functions identified.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <TableWrapper>
                <thead>
                  <tr>
                    <th style={{ width: '40%' }}>Target File Path</th>
                    <th style={{ width: '22%' }}>Vulnerability Type</th>
                    <th style={{ width: '12%' }}>Severity</th>
                    <th style={{ width: '26%' }}>Technical Analysis</th>
                  </tr>
                </thead>
                <tbody>
                  {vulns.map((item, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px', fontWeight: 600, color: 'text.primary' }}>
                        {item.file}
                      </td>
                      <td>
                        <Chip
                          size="small"
                          label={item.type}
                          color="error"
                          variant="outlined"
                          sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }}
                        />
                      </td>
                      <td>
                        <Chip
                          size="small"
                          label={item.severity}
                          sx={{
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 700,
                            bgcolor: item.severity === 'CRITICAL' ? '#DC2626' : '#EA580C',
                            color: '#FFFFFF',
                          }}
                        />
                      </td>
                      <td style={{ fontSize: '12.5px', color: 'text.secondary' }}>
                        {item.detail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>
            </Box>
          )}
        </Box>
      )}

      {/* Tab 1: Weak Crypto */}
      {activeTab === 1 && (
        <Box>
          {crypto.length === 0 ? (
            <Box sx={{ py: 3, textAlign: 'center' }}>
              <CheckCircleOutlineIcon sx={{ fontSize: 36, color: 'success.main', mb: 1 }} />
              <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 500 }}>
                No outdated or weak cryptographic algorithm implementations (DES, MD5, SHA1) detected.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <TableWrapper>
                <thead>
                  <tr>
                    <th style={{ width: '45%' }}>Target Binary / File</th>
                    <th style={{ width: '20%' }}>Algorithm / Key Pattern</th>
                    <th style={{ width: '12%' }}>Severity</th>
                    <th style={{ width: '23%' }}>Security Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {crypto.map((item, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px', fontWeight: 600, color: 'text.primary' }}>
                        {item.file}
                      </td>
                      <td>
                        <Chip
                          size="small"
                          label={item.algorithm}
                          color="warning"
                          sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 700 }}
                        />
                      </td>
                      <td>
                        <Chip
                          size="small"
                          label={item.severity}
                          sx={{
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 700,
                            bgcolor: item.severity === 'HIGH' ? '#EA580C' : '#CA8A04',
                            color: '#FFFFFF',
                          }}
                        />
                      </td>
                      <td style={{ fontSize: '12.5px', color: 'text.secondary' }}>
                        {item.detail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>
            </Box>
          )}
        </Box>
      )}

      {/* Tab 2: Default Credentials */}
      {activeTab === 2 && (
        <Box>
          {creds.length === 0 ? (
            <Box sx={{ py: 3, textAlign: 'center' }}>
              <CheckCircleOutlineIcon sx={{ fontSize: 36, color: 'success.main', mb: 1 }} />
              <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 500 }}>
                No default credentials, shadow hashes, or password files identified.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <TableWrapper>
                <thead>
                  <tr>
                    <th style={{ width: '45%' }}>Target File Path</th>
                    <th style={{ width: '25%' }}>Credential Classification</th>
                    <th style={{ width: '12%' }}>Severity</th>
                    <th style={{ width: '18%' }}>Audit Context</th>
                  </tr>
                </thead>
                <tbody>
                  {creds.map((item, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px', fontWeight: 600, color: 'text.primary' }}>
                        {item.file}
                      </td>
                      <td>
                        <Chip
                          size="small"
                          label={item.type}
                          color={item.severity === 'CRITICAL' ? 'error' : 'warning'}
                          variant="outlined"
                          sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }}
                        />
                      </td>
                      <td>
                        <Chip
                          size="small"
                          label={item.severity}
                          sx={{
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 700,
                            bgcolor: item.severity === 'CRITICAL' ? '#DC2626' : (item.severity === 'HIGH' ? '#EA580C' : '#2563EB'),
                            color: '#FFFFFF',
                          }}
                        />
                      </td>
                      <td style={{ fontSize: '12px', color: 'text.secondary' }}>
                        {item.detail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>
            </Box>
          )}
        </Box>
      )}

      {/* Tab 3: Configs & DBs */}
      {activeTab === 3 && (
        <Box>
          {configs.length === 0 ? (
            <Box sx={{ py: 3, textAlign: 'center' }}>
              <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                No sensitive configuration or database files identified.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <TableWrapper>
                <thead>
                  <tr>
                    <th style={{ width: '60%' }}>Detected Sensitive File Path</th>
                    <th style={{ width: '25%' }}>Category</th>
                    <th style={{ width: '15%' }}>Service Note</th>
                  </tr>
                </thead>
                <tbody>
                  {configs.map((item, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px', color: 'text.primary' }}>
                        {item.file}
                      </td>
                      <td>
                        <Chip
                          size="small"
                          label={item.category}
                          color="primary"
                          variant="outlined"
                          sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }}
                        />
                      </td>
                      <td style={{ fontSize: '12px', color: 'text.secondary' }}>
                        {item.detail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>
            </Box>
          )}
        </Box>
      )}

      {/* Tab 4: Network Endpoints */}
      {activeTab === 4 && (
        <Box>
          {endpoints.length === 0 ? (
            <Box sx={{ py: 3, textAlign: 'center' }}>
              <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                No IP addresses, remote URLs, or email contacts detected.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <TableWrapper>
                <thead>
                  <tr>
                    <th style={{ width: '8%' }}>#</th>
                    <th style={{ width: '20%' }}>Endpoint Type</th>
                    <th style={{ width: '52%' }}>Extracted Value</th>
                    <th style={{ width: '20%' }}>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((item, idx) => (
                    <tr key={idx}>
                      <td style={{ color: 'text.secondary', fontWeight: 600 }}>{idx + 1}</td>
                      <td>
                        <Chip
                          size="small"
                          label={item.type}
                          color={item.type === 'IP Address' ? 'info' : (item.type === 'URL Endpoint' ? 'primary' : 'secondary')}
                          sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }}
                        />
                      </td>
                      <td style={{ fontFamily: 'monospace', wordBreak: 'break-all', fontWeight: 600, color: item.type === 'IP Address' ? '#0284C7' : (item.type === 'URL Endpoint' ? '#2563EB' : '#059669') }}>
                        {item.type === 'URL Endpoint' ? (
                          <a href={item.value} target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'underline' }}>
                            {item.value}
                          </a>
                        ) : (
                          item.value
                        )}
                      </td>
                      <td style={{ fontSize: '12px', color: 'text.secondary' }}>
                        {item.detail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>
            </Box>
          )}
        </Box>
      )}

      {/* Tab 5: Shared Libraries */}
      {activeTab === 5 && (
        <Box>
          {sharedLibs.length === 0 ? (
            <Box sx={{ py: 3, textAlign: 'center' }}>
              <Typography variant="body2" sx={{ color: 'text.secondary', py: 2 }}>
                No dynamic library dependencies extracted from ELF binaries.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <TableWrapper>
                <thead>
                  <tr>
                    <th style={{ width: '45%' }}>ELF Executable / Binary</th>
                    <th style={{ width: '55%' }}>Linked Dynamic Libraries (DT_NEEDED)</th>
                  </tr>
                </thead>
                <tbody>
                  {sharedLibs.map((item, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px', fontWeight: 600, color: 'text.primary' }}>
                        {item.binary}
                      </td>
                      <td>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {item.libraries.map((lib, libIdx) => (
                            <Chip
                              key={libIdx}
                              size="small"
                              label={lib}
                              variant="outlined"
                              sx={{
                                borderRadius: '6px',
                                fontSize: '11px',
                                fontFamily: 'monospace',
                              }}
                            />
                          ))}
                        </Box>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>
            </Box>
          )}
        </Box>
      )}

      {/* Integrated Collapsible Raw Audit Stream Bar */}
      {Boolean(txtOutput) && (
        <Box sx={{ mt: 3, borderRadius: '12px', border: '1px solid', borderColor: 'divider', overflow: 'hidden', bgcolor: '#090D16' }}>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              px: 2,
              py: 1.2,
              borderBottom: showRawStream ? '1px solid #1E293B' : 'none',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <TerminalIcon sx={{ fontSize: 16, color: '#94A3B8' }} />
              <Typography variant="caption" sx={{ color: '#94A3B8', fontWeight: 600, fontFamily: 'monospace' }}>
                RAW FIRMAUDIT STREAM ({txtOutput.split('\n').filter(Boolean).length} lines)
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Button
                size="small"
                onClick={() => setShowRawStream(!showRawStream)}
                sx={{ color: '#38BDF8', fontSize: '11.5px', textTransform: 'none', fontWeight: 600, py: 0.2 }}
              >
                {showRawStream ? 'Hide Raw Log' : 'View Raw Log'}
              </Button>
              <Tooltip title={copied ? 'Copied!' : 'Copy Raw Log'}>
                <IconButton
                  size="small"
                  onClick={() => onCopy(txtOutput)}
                  sx={{ color: '#94A3B8', '&:hover': { color: '#FFFFFF' } }}
                >
                  {copied ? <CheckCircleOutlineIcon sx={{ fontSize: 16 }} color="success" /> : <ContentCopyIcon sx={{ fontSize: 16 }} />}
                </IconButton>
              </Tooltip>
            </Box>
          </Box>

          {showRawStream && (
            <Box
              sx={{
                p: 2,
                maxHeight: '350px',
                overflowY: 'auto',
                overflowX: 'auto',
                '&::-webkit-scrollbar': { width: '8px', height: '8px' },
                '&::-webkit-scrollbar-track': { backgroundColor: '#090D16' },
                '&::-webkit-scrollbar-thumb': { backgroundColor: '#334155', borderRadius: '4px' },
              }}
            >
              <Typography
                component="pre"
                sx={{
                  color: '#93C5FD',
                  fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
                  fontSize: '12px',
                  lineHeight: 1.5,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  m: 0,
                }}
              >
                {txtOutput}
              </Typography>
            </Box>
          )}
        </Box>
      )}
    </Paper>
  );
}
