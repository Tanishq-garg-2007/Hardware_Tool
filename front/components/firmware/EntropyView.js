import React from 'react';
import {
  Box,
  Button,
  Typography,
  CircularProgress,
  Paper,
  IconButton,
  Tooltip,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material';
import ShowChartIcon from '@mui/icons-material/ShowChart';
import ImageIcon from '@mui/icons-material/Image';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import TerminalIcon from '@mui/icons-material/Terminal';

export default function EntropyView({
  graphUrl,
  htmlOutput,
  pngUrl,
  txtOutput,
  graphFolderName,
  entropyViewMode,
  setEntropyViewMode,
  showRawStream,
  setShowRawStream,
  savedOutputPath,
  openFolderLoading,
  onOpenFolder,
  onCopy,
  copied,
}) {
  return (
    <Paper
      variant="outlined"
      sx={{
        borderRadius: '16px',
        backgroundColor: 'background.paper',
        borderColor: 'divider',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.05)',
        overflow: 'hidden',
      }}
    >
      {/* Card Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 1.5,
          px: 2.5,
          py: 1.5,
          borderBottom: '1px solid',
          borderColor: 'divider',
          backgroundColor: (theme) => (theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.01)'),
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2 }}>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 36,
              height: 36,
              borderRadius: '10px',
              bgcolor: 'primary.main',
              color: 'primary.contrastText',
            }}
          >
            <ShowChartIcon sx={{ fontSize: 20 }} />
          </Box>
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, lineHeight: 1.2 }}>
              Firmware Entropy Visualization
            </Typography>
            <Typography variant="caption" sx={{ color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 0.5 }}>
              Saved in <Box component="span" sx={{ fontFamily: 'monospace', fontWeight: 600, color: 'primary.main' }}>data/entropy_graph/{graphFolderName || ''}</Box>
            </Typography>
          </Box>
        </Box>

        {/* Header Controls */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          {pngUrl && (
            <ToggleButtonGroup
              size="small"
              value={entropyViewMode}
              exclusive
              onChange={(_, val) => val && setEntropyViewMode(val)}
              sx={{
                height: 30,
                '& .MuiToggleButton-root': {
                  px: 1.2,
                  py: 0.3,
                  fontSize: '11.5px',
                  textTransform: 'none',
                  fontWeight: 600,
                },
              }}
            >
              <ToggleButton value="interactive">
                <ShowChartIcon sx={{ fontSize: 15, mr: 0.5 }} /> Interactive
              </ToggleButton>
              <ToggleButton value="png">
                <ImageIcon sx={{ fontSize: 15, mr: 0.5 }} /> Static
              </ToggleButton>
            </ToggleButtonGroup>
          )}

          {savedOutputPath && onOpenFolder && (
            <Button
              size="small"
              variant="outlined"
              startIcon={openFolderLoading ? <CircularProgress size={13} color="inherit" /> : <FolderOpenIcon sx={{ fontSize: 16 }} />}
              onClick={() => onOpenFolder(savedOutputPath)}
              disabled={openFolderLoading}
              sx={{ borderRadius: '8px', textTransform: 'none', fontWeight: 600, fontSize: '11.5px', height: 30 }}
            >
              Open Folder
            </Button>
          )}

          {graphUrl && (
            <Button
              size="small"
              variant="outlined"
              startIcon={<OpenInNewIcon sx={{ fontSize: 16 }} />}
              onClick={() => window.open(graphUrl, '_blank')}
              sx={{ borderRadius: '8px', textTransform: 'none', fontWeight: 600, fontSize: '11.5px', height: 30 }}
            >
              Open in New Tab
            </Button>
          )}
        </Box>
      </Box>

      {/* Graph Viewer */}
      <Box sx={{ p: 0, bgcolor: '#0B0F19' }}>
        {entropyViewMode === 'interactive' && graphUrl ? (
          <iframe
            src={graphUrl}
            title="Firmware Entropy Plot"
            style={{
              width: '100%',
              height: '480px',
              border: 'none',
              display: 'block',
              backgroundColor: '#0F172A',
            }}
          />
        ) : pngUrl ? (
          <Box sx={{ p: 2.5, display: 'flex', justifyContent: 'center', alignItems: 'center', bgcolor: '#0F172A' }}>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={pngUrl}
              alt="Entropy Plot"
              style={{
                maxWidth: '100%',
                height: 'auto',
                maxHeight: '480px',
                borderRadius: '8px',
              }}
            />
          </Box>
        ) : htmlOutput ? (
          <iframe
            srcDoc={htmlOutput}
            title="Firmware Entropy Plot"
            style={{
              width: '100%',
              height: '480px',
              border: 'none',
              display: 'block',
              backgroundColor: '#0F172A',
            }}
          />
        ) : null}
      </Box>

      {/* Integrated Collapsible Raw Chunk Stream */}
      {Boolean(txtOutput) && (
        <Box sx={{ borderTop: '1px solid', borderColor: 'divider', bgcolor: '#090D16' }}>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              px: 2.5,
              py: 1.2,
              borderBottom: showRawStream ? '1px solid #1E293B' : 'none',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <TerminalIcon sx={{ fontSize: 16, color: '#94A3B8' }} />
              <Typography variant="caption" sx={{ color: '#94A3B8', fontWeight: 600, fontFamily: 'monospace' }}>
                RAW CHUNK STREAM ({txtOutput.split('\n').filter(Boolean).length} chunks)
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Button
                size="small"
                onClick={() => setShowRawStream(!showRawStream)}
                sx={{ color: '#38BDF8', fontSize: '11.5px', textTransform: 'none', fontWeight: 600, py: 0.2 }}
              >
                {showRawStream ? 'Hide Data' : 'View Data'}
              </Button>
              <Tooltip title={copied ? 'Copied!' : 'Copy Stream'}>
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
                maxHeight: '280px',
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
