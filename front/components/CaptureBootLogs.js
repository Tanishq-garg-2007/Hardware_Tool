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
import DescriptionIcon from '@mui/icons-material/Description';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const CaptureBootLogs = ({ onBack }) => {
  const baudrateRef = useRef();
  const timeRef = useRef();
  const rebootDelayRef = useRef();
  const router = useRouter();
  const [loading, setLoading] = useState(false);
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
    const baudrate = baudrateRef.current?.value?.trim() || '115200';
    const time = timeRef.current?.value?.trim() || '10';
    const rebootDelay = rebootDelayRef.current?.value?.trim() || '5';

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/capture_boot_logs/${time}/${rebootDelay}/${baudrate}`
      );

      if (!response.ok) {
        throw new Error(`Server returned status ${response.status}`);
      }

      const data = await response.json();
      if (!data.success && data.error) {
        throw new Error(data.error);
      }
      if (typeof data.data === 'string' && data.data.startsWith('[ERROR]')) {
        throw new Error(data.data);
      }
      router.push({
        pathname: '/reports',
        query: { report: data.data },
      });
    } catch (e) {
      setError(e.message || 'Failed to capture bootlogs.');
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
          <DescriptionIcon color="primary" /> Capture Live Hardware Boot Logs
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
          Power cycles the target device and streams raw UART bootloader & kernel serial output directly to memory and disk.
        </Typography>

        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr 1fr' }, gap: 1.5, mt: 1 }}>
          <TextField
            label="Baudrate"
            placeholder="115200"
            size="small"
            type="number"
            inputRef={baudrateRef}
            variant="outlined"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
          />
          <TextField
            label="Sample Time (Sec)"
            placeholder="10"
            size="small"
            type="number"
            inputRef={timeRef}
            variant="outlined"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
          />
          <TextField
            label="Reboot Delay (Sec)"
            placeholder="5"
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
          startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <DescriptionIcon />}
          sx={{ borderRadius: '10px', fontWeight: 600, py: 1, mt: 1 }}
        >
          {loading ? 'Capturing Live Boot Log...' : 'Start Boot Log Capture'}
        </Button>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ borderRadius: '12px' }}>
          {error}
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

export default CaptureBootLogs;
