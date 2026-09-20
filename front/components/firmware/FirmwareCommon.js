import React from 'react';
import { Box, Paper, Typography } from '@mui/material';

export function MetricCard({ title, count, color, icon }) {
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
        {icon && React.cloneElement(icon, { sx: { fontSize: 18 } })}
      </Box>
      <Typography variant="h4" sx={{ fontWeight: 800, color }}>
        {count}
      </Typography>
    </Paper>
  );
}

export function TableWrapper({ children }) {
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

export function parseFirmAuditOutput(reportText) {
  if (!reportText || typeof reportText !== 'string') {
    return {
      summary: {
        vulnerabilities: 0,
        weak_crypto: 0,
        credentials: 0,
        configs_and_dbs: 0,
        network_endpoints: 0,
        shared_libraries: 0,
      },
      vulnerabilities: [],
      weak_crypto: [],
      credentials: [],
      configs_and_dbs: [],
      network_endpoints: [],
      shared_libraries: [],
    };
  }

  const lines = reportText.split('\n');
  const vulnerabilities = [];
  const weak_crypto = [];
  const credentials = [];
  const configs_and_dbs = [];
  const network_endpoints = [];
  const shared_libraries = [];

  let currentSection = null;
  let libFile = null;

  const seenVulns = new Set();
  const seenCrypto = new Set();
  const seenCreds = new Set();
  const seenFiles = new Set();
  const seenEndpoints = new Set();

  const coreutilsApplets = new Set([
    'cat', 'catv', 'chgrp', 'chmod', 'chown', 'cp', 'cpio', 'date', 'dd', 'df',
    'dmesg', 'echo', 'false', 'fgrep', 'free', 'fsync', 'getopt', 'grep', 'gunzip',
    'gzip', 'hostname', 'iostat', 'kill', 'killall', 'killall5', 'ln', 'ls', 'lsattr',
    'mkdir', 'mknod', 'more', 'mount', 'mountpoint', 'mpstat', 'mt', 'mv', 'nice',
    'pidof', 'ping', 'powertop', 'printenv', 'ps', 'pwd', 'rm', 'rmdir', 'sed',
    'sleep', 'stat', 'stty', 'sync', 'tar', 'touch', 'true', 'umount', 'uname',
    'uncompress', 'usleep', 'vi', 'watch', 'zcat', 'ash', 'sh', 'egrep', 'mktemp',
    'fdflush', 'dumpkmap', 'loadkmap', 'setarch', 'linux32', 'linux64', 'cttyhack',
    'base64', 'scriptreplay', 'ipcalc', 'ionice', 'dnsdomainname', 'chattr'
  ]);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    if (line.includes('Searching in ') && line.includes('directory')) continue;
    if (line.includes('Searching for IP addresses')) { currentSection = 'ip'; continue; }
    if (line.includes('Searching for important binaries')) { currentSection = 'binaries'; continue; }
    if (line.includes('Searching for Database file')) { currentSection = 'database'; continue; }
    if (line.includes('Searching for system configuration files')) { currentSection = 'configs'; continue; }
    if (line.includes('Searching for passwords')) { currentSection = 'passwords'; continue; }
    if (line.includes('Searching for files')) { currentSection = 'files'; continue; }
    if (line.includes('Searching for ssh files')) { currentSection = 'ssh_files'; continue; }
    if (line.includes('Searching for ssl files')) { currentSection = 'ssl_files'; continue; }
    if (line.includes('Searching for webserveres')) { currentSection = 'webservers'; continue; }
    if (line.includes('Searching for shell scripts')) { currentSection = 'scripts'; continue; }
    if (line.includes('Searching for .bin files')) { currentSection = 'bin_files'; continue; }
    if (line.includes('Searching for email addresses')) { currentSection = 'emails'; continue; }
    if (line.includes('Searching for urls')) { currentSection = 'urls'; continue; }
    if (line.includes('Searching for default credentials')) { currentSection = 'default_creds_files'; continue; }
    if (line.includes('Searching for hardcoded sensitive information')) { currentSection = 'sensitive_info'; continue; }
    if (line.includes('Searching for insecure services')) { currentSection = 'insecure_services'; continue; }
    if (line.includes('Searching for misconfigurations')) { currentSection = 'misconfigs'; continue; }
    if (line.includes('Identifying file signatures')) { currentSection = 'signatures'; continue; }
    if (line.includes('Identifying third-party libraries in ELF files')) { currentSection = 'third_party_libs'; continue; }
    if (line.includes('Identifying dangerous functions in ELF files')) { currentSection = 'dangerous_functions'; continue; }
    if (line.includes('Searching for hardcoded SSH keys')) { currentSection = 'ssh_keys'; continue; }
    if (line.includes('Searching for command injection vulnerabilities')) { currentSection = 'command_injection'; continue; }
    if (line.includes('Searching for outdated or weak cryptographic algorithms')) { currentSection = 'weak_crypto'; continue; }
    if (line.includes('Checking for weak or predictable encryption keys')) { currentSection = 'weak_keys'; continue; }
    if (line.includes('Searching for Default Credentials in System Binaries')) { currentSection = 'default_credentials_binaries'; continue; }

    if (line.startsWith('########################')) continue;

    // 1. Command injection
    const matchCI = line.match(/^File:\s*(.*?)\s*-\s*Potential command injection vulnerability/i);
    if (matchCI) {
      const fpath = matchCI[1].trim();
      if (!seenVulns.has(fpath)) {
        seenVulns.add(fpath);
        vulnerabilities.push({
          file: fpath,
          type: 'Command Injection',
          severity: 'CRITICAL',
          detail: 'Potential shell execution or command injection vector detected in web interface or script.',
        });
      }
      continue;
    }

    // 2. Dangerous function
    const matchDF = line.match(/^File:\s*(.*?)\s*-\s*Dangerous Function:\s*(.*)/i);
    if (matchDF) {
      const fpath = matchDF[1].trim();
      const func = matchDF[2].trim();
      const key = `${fpath}:${func}`;
      if (!seenVulns.has(key)) {
        seenVulns.add(key);
        vulnerabilities.push({
          file: fpath,
          type: `Dangerous Function (${func})`,
          severity: 'HIGH',
          detail: `Deprecated or dangerous memory API symbol '${func}' found in ELF symbol table.`,
        });
      }
      continue;
    }

    // 3. Hardcoded SSH key
    const matchSSH = line.match(/^File:\s*(.*?)\s*-\s*Contains hardcoded SSH key/i);
    if (matchSSH) {
      const fpath = matchSSH[1].trim();
      if (!seenVulns.has(fpath)) {
        seenVulns.add(fpath);
        vulnerabilities.push({
          file: fpath,
          type: 'Hardcoded SSH Private Key',
          severity: 'CRITICAL',
          detail: 'Embedded private key banner (RSA/DSA/EC) found inside binary or file.',
        });
      }
      continue;
    }

    // 4. Weak Crypto Algorithms
    const matchWC = line.match(/^File:\s*(.*?)\s*-\s*(MD5|SHA1|DES|RC4)\b/i);
    if (matchWC) {
      const fpath = matchWC[1].trim();
      const algo = matchWC[2].trim().toUpperCase();
      const key = `${fpath}:${algo}`;
      if (!seenCrypto.has(key)) {
        seenCrypto.add(key);
        weak_crypto.push({
          file: fpath,
          algorithm: algo,
          severity: (algo === 'DES' || algo === 'RC4') ? 'HIGH' : 'MEDIUM',
          detail: `Outdated, broken, or collision-prone cryptographic algorithm '${algo}' used.`,
        });
      }
      continue;
    }

    // 5. Weak keys
    const matchWK = line.match(/^File:\s*(.*?)\s*-\s*Contains weak or predictable encryption key:\s*(.*)/i);
    if (matchWK) {
      const fpath = matchWK[1].trim();
      const kdetail = matchWK[2].trim();
      const key = `${fpath}:${kdetail}`;
      if (!seenCrypto.has(key)) {
        seenCrypto.add(key);
        weak_crypto.push({
          file: fpath,
          algorithm: 'Predictable Key Pattern',
          severity: 'HIGH',
          detail: `Predictable static key or password pattern: ${kdetail}`,
        });
      }
      continue;
    }

    // 6. Default Credentials in Binaries / System files
    const matchDC = line.match(/^File:\s*(.*?)\s*-\s*Contains default credentials/i);
    if (matchDC) {
      const fpath = matchDC[1].trim();
      const fname = fpath.split('/').pop().toLowerCase();
      const isConfigOrScript = ['/etc/', '.conf', '.cfg', '.sh', '.json', '.xml', 'init', 'rc.'].some(x => fpath.toLowerCase().includes(x));
      const isDaemon = ['login', 'telnet', 'ftp', 'ssh', 'dropbear', 'updater', 'sysctl', 'admin', 'auth'].some(x => fname.includes(x));

      if (coreutilsApplets.has(fname) && !isConfigOrScript) {
        continue;
      }

      if (!seenCreds.has(fpath)) {
        seenCreds.add(fpath);
        let ctype = 'Default Credentials in Binary';
        let csev = 'MEDIUM';
        if (isConfigOrScript) {
          ctype = 'Default Credentials in Config/Script';
          csev = 'CRITICAL';
        } else if (isDaemon) {
          ctype = 'Default Credentials in Daemon Binary';
          csev = 'HIGH';
        }
        credentials.push({
          file: fpath,
          type: ctype,
          severity: csev,
          detail: 'Default credential pair (admin/admin, root/root, etc.) detected.',
        });
      }
      continue;
    }

    // 7. Password / Shadow / PSK Files
    if (currentSection === 'passwords') {
      if (!seenCreds.has(line)) {
        seenCreds.add(line);
        const fname = line.split('/').pop();
        credentials.push({
          file: line,
          type: (fname.includes('shadow') || fname.includes('passwd')) ? 'Password / Shadow Hash File' : 'Pre-Shared Key / Secret File',
          severity: 'CRITICAL',
          detail: `Sensitive user credential or hash storage file: ${fname}`,
        });
      }
      continue;
    }

    // 8. Third-party dynamic libraries
    if (currentSection === 'third_party_libs') {
      if (line.startsWith('File:')) {
        libFile = line.replace('File:', '').trim();
      } else if (libFile && (line.includes('.so') || line.includes('libc'))) {
        const libs = line.split(',').map(l => l.trim()).filter(Boolean);
        shared_libraries.push({
          binary: libFile,
          libraries: libs,
        });
        libFile = null;
      }
      continue;
    }

    // 9. Configs, Databases, and Sensitive Files
    if (['configs', 'database', 'binaries', 'ssl_files', 'ssh_files', 'webservers'].includes(currentSection)) {
      const catMap = {
        configs: 'System Configuration',
        database: 'Database File',
        binaries: 'Critical Service Binary',
        ssl_files: 'SSL Certificate / Key',
        ssh_files: 'SSH Configuration / Key',
        webservers: 'Web Server Executable',
      };
      if (!seenFiles.has(line) && !line.startsWith('File:')) {
        seenFiles.add(line);
        configs_and_dbs.push({
          file: line,
          category: catMap[currentSection] || 'System File',
          detail: `${catMap[currentSection] || 'System File'} discovered during deep audit`,
        });
      }
      continue;
    }

    // 10. Network Endpoints
    if (currentSection === 'ip') {
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(line)) {
        if (!seenEndpoints.has(line)) {
          seenEndpoints.add(line);
          network_endpoints.push({
            type: 'IP Address',
            value: line,
            detail: 'Hardcoded IPv4 address',
          });
        }
      }
      continue;
    } else if (currentSection === 'urls') {
      if (line.startsWith('http://') || line.startsWith('https://')) {
        const cleanUrl = line.replace(/['";)>.]+$/, '');
        if (!seenEndpoints.has(cleanUrl)) {
          seenEndpoints.add(cleanUrl);
          network_endpoints.push({
            type: 'URL Endpoint',
            value: cleanUrl,
            detail: 'Discovered remote HTTP/HTTPS resource URL',
          });
        }
      }
      continue;
    } else if (currentSection === 'emails') {
      if (line.includes('@') && !seenEndpoints.has(line)) {
        seenEndpoints.add(line);
        network_endpoints.push({
          type: 'Email Contact',
          value: line,
          detail: 'Developer / vendor contact email address',
        });
      }
      continue;
    }
  }

  return {
    summary: {
      vulnerabilities: vulnerabilities.length,
      weak_crypto: weak_crypto.length,
      credentials: credentials.length,
      configs_and_dbs: configs_and_dbs.length,
      network_endpoints: network_endpoints.length,
      shared_libraries: shared_libraries.length,
    },
    vulnerabilities,
    weak_crypto,
    credentials,
    configs_and_dbs,
    network_endpoints,
    shared_libraries,
  };
}
