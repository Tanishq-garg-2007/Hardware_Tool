import React, { useRef, useState } from 'react';
import {
  Button,
  TextField,
  Typography,
  Box,
  CircularProgress,
  Paper,
  Alert,
} from '@mui/material';
import { useRouter } from 'next/router';
import TerminalIcon from '@mui/icons-material/Terminal';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const CheckUARTConsole = ({ onBack }) => {
  const router = useRouter();
  const baudrateRef = useRef();
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleBack = () => {
    if (onBack) {
      onBack();
    } else if (router?.query?.mode) {
      router.push(`/dashboard?mode=${router.query.mode}`);
    } else if (typeof window !== 'undefined' && window.history.length > 1) {
      router.back();
    } else {
      router.push('/dashboard');
    }
  };

  const handleSubmit = async () => {
    const baudrate = baudrateRef.current?.value?.trim() || '115200';

    try {
      setLoading(true);
      setError(null);
      setResult(null);

      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/check_uart_console/${baudrate}?power_delay=3&listen_time=5`
      );

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || 'Failed to query UART console from server.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ maxWidth: '600px', display: 'flex', flexDirection: 'column', gap: 2.5 }}>
      <Paper
        variant="outlined"
        sx={{
          p: 3,
          borderRadius: '16px',
          backgroundColor: 'background.default',
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
        }}
      >
        <Typography variant="subtitle1" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
          <TerminalIcon color="primary" /> Check for Interactive UART Console
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
          Sends interactive newline keystrokes over UART to check for responsive shell prompts (e.g. root, sh, login, U-Boot).
        </Typography>

        <TextField
          fullWidth
          size="small"
          label="Baudrate"
          placeholder="115200"
          inputRef={baudrateRef}
          type="number"
          variant="outlined"
          sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
        />

        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={loading}
          startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <TerminalIcon />}
          sx={{ borderRadius: '10px', fontWeight: 600, py: 1 }}
        >
          {loading ? 'Checking Console...' : 'Probe UART Console'}
        </Button>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ borderRadius: '12px' }}>
          {error}
        </Alert>
      )}

      {result && (
        <Alert
          icon={result.is_available ? <CheckCircleIcon fontSize="inherit" /> : undefined}
          severity={
            !result.success
              ? 'error'
              : result.is_available
                ? 'success'
                : 'warning'
          }
          sx={{ borderRadius: '12px', alignItems: 'flex-start' }}
        >
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
            {!result.success
              ? 'UART Communication Error'
              : result.is_available
                ? 'Interactive UART Console Available'
                : result.is_garbage
                  ? 'Garbage Output Detected'
                  : 'No Interactive Console Detected'}
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {result.message || result.data}
          </Typography>
          {result.log && result.log !== result.message && (
            <Box
              component="pre"
              sx={{
                mt: 1,
                p: 1.5,
                borderRadius: '8px',
                backgroundColor: 'background.paper',
                fontSize: '11px',
                fontFamily: 'monospace',
                maxHeight: '160px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {result.log}
            </Box>
          )}
        </Alert>
      )}

      {/* Bottom Back Button */}
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3, mb: 1 }}>
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
          Back to Dashboard
        </Button>
      </Box>
    </Box>
  );
};

export default CheckUARTConsole;
