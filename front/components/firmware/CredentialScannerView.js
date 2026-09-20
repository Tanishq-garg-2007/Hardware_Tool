import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  CircularProgress,
  Grid,
  Tabs,
  Tab,
  Chip,
} from '@mui/material';
import KeyIcon from '@mui/icons-material/Key';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import FolderIcon from '@mui/icons-material/Folder';
import LanguageIcon from '@mui/icons-material/Language';
import LinkIcon from '@mui/icons-material/Link';
import SearchIcon from '@mui/icons-material/Search';
import { MetricCard, TableWrapper } from './FirmwareCommon';

export default function CredentialScannerView({
  credentialDirectory,
  setCredentialDirectory,
  credentialLoading,
  handleCredentialScan,
  credentialResults,
}) {
  const [activeTab, setActiveTab] = useState(0);

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

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 3,
        borderRadius: '16px',
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
  );
}
