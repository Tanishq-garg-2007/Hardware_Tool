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
import SpeedIcon from '@mui/icons-material/Speed';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

const NewDetectBaudrate = ({ setReport }) => {
  const timeRef = useRef();
  const rebootDelayRef = useRef();
  const [loading, setLoading] = useState(false);
  const [hasRun, setHasRun] = useState(false);
  const [bestBaud, setBestBaud] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async () => {
    const time = timeRef.current?.value || '5';
    const rebootDelay = rebootDelayRef.current?.value || '2';

    setLoading(true);
    setHasRun(false);
    setBestBaud(null);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/new_detect_baudrate/${time}/${rebootDelay}`
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
          <SpeedIcon color="primary" /> Auto-Detect UART Baudrate (Octocoupler)
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
          Uses isolated power switching to power cycle the device and evaluate UART traffic characteristics across standard baudrates.
        </Typography>

        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' }, gap: 2, mt: 1 }}>
          <TextField
            label="Sampling Duration (Sec)"
            defaultValue="5"
            size="small"
            type="number"
            inputRef={timeRef}
            variant="outlined"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
          />
          <TextField
            label="Reboot Delay (Sec)"
            defaultValue="2"
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
          {loading ? 'Detecting Baudrate...' : 'Start Octocoupler Baudrate Detection'}
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
              Optimal Detected Baudrate: <Chip label={bestBaud} color="success" size="small" sx={{ fontWeight: 700, ml: 1 }} />
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
    </Box>
  );
};

export default NewDetectBaudrate;
