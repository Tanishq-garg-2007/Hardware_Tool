import React, { useState } from 'react';
import {
  Box,
  Button,
  Typography,
  CircularProgress,
  Paper,
  Chip,
  Tabs,
  Tab,
  IconButton,
  Tooltip,
  TablePagination,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import TerminalIcon from '@mui/icons-material/Terminal';
import { TableWrapper, parseFirmAuditOutput } from './FirmwareCommon';

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
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  const handleTabChange = (_, newTab) => {
    setActiveTab(newTab);
    setPage(0);
  };

  const auditData = firmAuditResults || parseFirmAuditOutput(txtOutput);
  const rawVulns = auditData.vulnerabilities || [];
  const crypto = auditData.weak_crypto || [];
  const rawCreds = auditData.credentials || [];
  const endpoints = auditData.network_endpoints || [];

  // Filter 2.a: Only show 'Dangerous Function (sprintf)' and 'Hardcoded SSH Private Key'
  const vulns = rawVulns.filter(
    (item) => item.type === 'Dangerous Function (sprintf)' || item.type === 'Hardcoded SSH Private Key'
  );

  // Filter 2.c: Only keep 'Password / Shadow Hash File' rows
  const creds = rawCreds.filter(
    (item) => item.type === 'Password / Shadow Hash File'
  );

  // Paginated slices
  const currentVulns = vulns.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
  const currentCrypto = crypto.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
  const currentCreds = creds.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
  const currentEndpoints = endpoints.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);

  const renderSeverityChip = (severity) => {
    const s = (severity || '').toUpperCase();
    let bg = '#DC2626';
    if (s.includes('CRIT')) {
      bg = '#DC2626';
    } else if (s.includes('HIGH')) {
      bg = '#EA580C';
    } else if (s.includes('MED')) {
      bg = '#D97706';
    } else if (s.includes('LOW')) {
      bg = '#2563EB';
    } else {
      bg = '#64748B';
    }

    return (
      <Chip
        size="small"
        label={severity || 'UNKNOWN'}
        sx={{
          borderRadius: '6px',
          fontSize: '11px',
          fontWeight: 700,
          bgcolor: bg,
          color: '#FFFFFF',
          minWidth: '68px',
          textAlign: 'center',
        }}
      />
    );
  };

  return (
    <Paper
      variant="outlined"
      sx={{
        p: { xs: 2.5, sm: 3.5 },
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
            </Box>
            <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.3, fontSize: '12.5px' }}>
              Prioritized security triage: dangerous memory functions, hardcoded keys, weak cryptography, and credential artifacts.
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

      {/* Simplified, Modern Category Tabs with Integrated Count Badges */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2.5 }}>
        <Tabs
          value={activeTab}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            '& .MuiTab-root': {
              textTransform: 'none',
              fontWeight: 600,
              fontSize: '13.5px',
              minHeight: '46px',
              py: 1,
              px: 2,
            },
          }}
        >
          <Tab
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <span>Vulnerabilities</span>
                <Chip
                  size="small"
                  label={vulns.length}
                  color={vulns.length > 0 ? 'error' : 'default'}
                  sx={{ height: 20, fontSize: '11px', fontWeight: 700, borderRadius: '6px' }}
                />
              </Box>
            }
          />
          <Tab
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <span>Weak Crypto</span>
                <Chip
                  size="small"
                  label={crypto.length}
                  color={crypto.length > 0 ? 'warning' : 'default'}
                  sx={{ height: 20, fontSize: '11px', fontWeight: 700, borderRadius: '6px' }}
                />
              </Box>
            }
          />
          <Tab
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <span>Default Credentials</span>
                <Chip
                  size="small"
                  label={creds.length}
                  sx={{
                    height: 20,
                    fontSize: '11px',
                    fontWeight: 700,
                    borderRadius: '6px',
                    bgcolor: creds.length > 0 ? '#DC2626' : 'action.disabledBackground',
                    color: creds.length > 0 ? '#FFFFFF' : 'text.disabled',
                  }}
                />
              </Box>
            }
          />
          <Tab
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <span>Network Endpoints</span>
                <Chip
                  size="small"
                  label={endpoints.length}
                  color={endpoints.length > 0 ? 'info' : 'default'}
                  sx={{ height: 20, fontSize: '11px', fontWeight: 700, borderRadius: '6px' }}
                />
              </Box>
            }
          />
        </Tabs>
      </Box>

      {/* Tab 0: Vulnerabilities */}
      {activeTab === 0 && (
        <Box>
          {vulns.length === 0 ? (
            <Box sx={{ py: 4, textAlign: 'center' }}>
              <CheckCircleOutlineIcon sx={{ fontSize: 36, color: 'success.main', mb: 1 }} />
              <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 500 }}>
                No dangerous sprintf functions or hardcoded SSH private keys identified.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <TableWrapper>
                <thead>
                  <tr>
                    <th style={{ width: '52%' }}>Target File Path</th>
                    <th style={{ width: '30%' }}>Vulnerability Type</th>
                    <th style={{ width: '18%' }}>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {currentVulns.map((item, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px', fontWeight: 600, color: 'text.primary' }}>
                        {item.file}
                      </td>
                      <td>
                        <Chip
                          size="small"
                          label={item.type}
                          color={item.type === 'Hardcoded SSH Private Key' ? 'error' : 'warning'}
                          variant="outlined"
                          sx={{ borderRadius: '6px', fontSize: '11px', fontWeight: 600 }}
                        />
                      </td>
                      <td>
                        {renderSeverityChip(item.severity || (item.type === 'Hardcoded SSH Private Key' ? 'CRITICAL' : 'HIGH'))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>

              <TablePagination
                component="div"
                count={vulns.length}
                page={page}
                onPageChange={(_, newPage) => setPage(newPage)}
                rowsPerPage={rowsPerPage}
                onRowsPerPageChange={(e) => {
                  setRowsPerPage(parseInt(e.target.value, 10));
                  setPage(0);
                }}
                rowsPerPageOptions={[10, 25, 50]}
                sx={{
                  borderTop: '1px solid',
                  borderColor: 'divider',
                  px: 1,
                  py: 0.5,
                  '& .MuiTablePagination-toolbar': { minHeight: '44px', fontSize: '12.5px' },
                }}
              />
            </Box>
          )}
        </Box>
      )}

      {/* Tab 1: Weak Crypto */}
      {activeTab === 1 && (
        <Box>
          {crypto.length === 0 ? (
            <Box sx={{ py: 4, textAlign: 'center' }}>
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
                    <th style={{ width: '52%' }}>Target Binary / File</th>
                    <th style={{ width: '30%' }}>Algorithm / Key Pattern</th>
                    <th style={{ width: '18%' }}>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {currentCrypto.map((item, idx) => (
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
                        {renderSeverityChip(item.severity || ((item.algorithm === 'DES' || item.algorithm === 'RC4' || item.algorithm === 'Predictable Key Pattern') ? 'HIGH' : 'MEDIUM'))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>

              <TablePagination
                component="div"
                count={crypto.length}
                page={page}
                onPageChange={(_, newPage) => setPage(newPage)}
                rowsPerPage={rowsPerPage}
                onRowsPerPageChange={(e) => {
                  setRowsPerPage(parseInt(e.target.value, 10));
                  setPage(0);
                }}
                rowsPerPageOptions={[10, 25, 50]}
                sx={{
                  borderTop: '1px solid',
                  borderColor: 'divider',
                  px: 1,
                  py: 0.5,
                  '& .MuiTablePagination-toolbar': { minHeight: '44px', fontSize: '12.5px' },
                }}
              />
            </Box>
          )}
        </Box>
      )}

      {/* Tab 2: Default Credentials */}
      {activeTab === 2 && (
        <Box>
          {creds.length === 0 ? (
            <Box sx={{ py: 4, textAlign: 'center' }}>
              <CheckCircleOutlineIcon sx={{ fontSize: 36, color: 'success.main', mb: 1 }} />
              <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 500 }}>
                No sensitive password or shadow hash files identified.
              </Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <TableWrapper>
                <thead>
                  <tr>
                    <th style={{ width: '52%' }}>Target File Path</th>
                    <th style={{ width: '30%' }}>Credential Classification</th>
                    <th style={{ width: '18%' }}>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {currentCreds.map((item, idx) => (
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
                        {renderSeverityChip(item.severity || 'CRITICAL')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </TableWrapper>

              <TablePagination
                component="div"
                count={creds.length}
                page={page}
                onPageChange={(_, newPage) => setPage(newPage)}
                rowsPerPage={rowsPerPage}
                onRowsPerPageChange={(e) => {
                  setRowsPerPage(parseInt(e.target.value, 10));
                  setPage(0);
                }}
                rowsPerPageOptions={[10, 25, 50]}
                sx={{
                  borderTop: '1px solid',
                  borderColor: 'divider',
                  px: 1,
                  py: 0.5,
                  '& .MuiTablePagination-toolbar': { minHeight: '44px', fontSize: '12.5px' },
                }}
              />
            </Box>
          )}
        </Box>
      )}

      {/* Tab 3: Network Endpoints */}
      {activeTab === 3 && (
        <Box>
          {endpoints.length === 0 ? (
            <Box sx={{ py: 4, textAlign: 'center' }}>
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
                    <th style={{ width: '22%' }}>Endpoint Type</th>
                    <th style={{ width: '45%' }}>Extracted Value</th>
                    <th style={{ width: '25%' }}>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {currentEndpoints.map((item, idx) => {
                    const itemNumber = page * rowsPerPage + idx + 1;
                    return (
                      <tr key={idx}>
                        <td style={{ color: 'text.secondary', fontWeight: 600 }}>{itemNumber}</td>
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
                    );
                  })}
                </tbody>
              </TableWrapper>

              <TablePagination
                component="div"
                count={endpoints.length}
                page={page}
                onPageChange={(_, newPage) => setPage(newPage)}
                rowsPerPage={rowsPerPage}
                onRowsPerPageChange={(e) => {
                  setRowsPerPage(parseInt(e.target.value, 10));
                  setPage(0);
                }}
                rowsPerPageOptions={[10, 25, 50]}
                sx={{
                  borderTop: '1px solid',
                  borderColor: 'divider',
                  px: 1,
                  py: 0.5,
                  '& .MuiTablePagination-toolbar': { minHeight: '44px', fontSize: '12.5px' },
                }}
              />
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
