import React, { useRef, useState } from 'react';
import {
  Box,
  Button,
  TextField,
  Typography,
  Paper,
  CircularProgress,
  Alert,
  Chip,
} from '@mui/material';
import { useRouter } from 'next/router';
import SpeedIcon from '@mui/icons-material/Speed';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const DetectBaudrate = ({ setReport, onBack }) => {
  const router = useRouter();
  const timeRef = useRef();
  const rebootDelayRef = useRef();
  const [loading, setLoading] = useState(false);
  const [hasRun, setHasRun] = useState(false);
  const [bestBaud, setBestBaud] = useState(null);
  const [error, setError] = useState(null);

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
    const time = timeRef.current?.value?.trim() || '5';
    const rebootDelay = rebootDelayRef.current?.value?.trim() || '3';

    setLoading(true);
    setHasRun(false);
    setBestBaud(null);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/detect_baudrate/${time}/${rebootDelay}`
      );

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();

      if (setReport && data.log) {
        setReport(data.log);
      }

      setBestBaud(data.best_baud);
      setHasRun(true);
    } catch (e) {
      setError(e.message || 'Failed to detect baudrate.');
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
          <SpeedIcon color="primary" /> Auto-Detect UART Baudrate
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
          Powers on the target device and samples UART signal across common baudrates to identify valid ASCII console output.
        </Typography>

        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' }, gap: 2, mt: 1 }}>
          <TextField
            label="Sampling Duration (Sec)"
            placeholder="5"
            size="small"
            type="number"
            inputRef={timeRef}
            variant="outlined"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
          />
          <TextField
            label="Reboot Delay (Sec)"
            placeholder="3"
            size="small"
            type="number"
            inputRef={rebootDelayRef}
            variant="outlined"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
          />
        </Box>

        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={loading}
          startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <SpeedIcon />}
          sx={{ borderRadius: '10px', fontWeight: 600, py: 1, mt: 1 }}
        >
          {loading ? 'Detecting Baudrate...' : 'Start Baudrate Detection'}
        </Button>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ borderRadius: '12px' }}>
          {error}
        </Alert>
      )}

      {hasRun && !loading && (
        bestBaud ? (
          <Alert
            icon={<CheckCircleIcon fontSize="inherit" />}
            severity="success"
            sx={{ borderRadius: '12px', alignItems: 'center' }}
          >
            <Typography variant="body1" sx={{ fontWeight: 700 }}>
              Detected Baudrate: <Chip label={bestBaud} color="success" size="small" sx={{ fontWeight: 700, ml: 1 }} />
            </Typography>
          </Alert>
        ) : (
          <Alert
            severity="warning"
            sx={{ borderRadius: '12px', alignItems: 'flex-start' }}
          >
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
              No Valid Baudrate Detected
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              None of the tested baudrates (115200, 9600, 57600, 38400, 19200, 4800) produced valid readable UART console output. Please verify that TX/RX pins are connected properly, the device shares a common ground (GND), and target power is enabled.
            </Typography>
          </Alert>
        )
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

export default DetectBaudrate;
