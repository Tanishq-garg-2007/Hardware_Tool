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

const NewCaptureBootLog = () => {
  const baudrateRef = useRef();
  const timeRef = useRef();
  const rebootDelayRef = useRef();
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async () => {
    const baudrate = baudrateRef.current?.value || '115200';
    const time = timeRef.current?.value || '10';
    const rebootDelay = rebootDelayRef.current?.value || '2';

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/new_capture_boot_logs/${time}/${rebootDelay}/${baudrate}`
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
      setError(e.message || 'Failed to capture bootlogs via Octocoupler.');
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
          <DescriptionIcon color="primary" /> Capture Live Boot Logs (Octocoupler)
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
          Uses the Octocoupler switching channel to cycle target hardware power and record early stage bootloader execution strings.
        </Typography>

        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr 1fr' }, gap: 1.5, mt: 1 }}>
          <TextField
            label="Baudrate"
            defaultValue="115200"
            size="small"
            type="number"
            inputRef={baudrateRef}
            variant="outlined"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
          />
          <TextField
            label="Sample Time (Sec)"
            defaultValue="10"
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
          startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <DescriptionIcon />}
          sx={{ borderRadius: '10px', fontWeight: 600, py: 1, mt: 1 }}
        >
          {loading ? 'Capturing Octocoupler Boot Log...' : 'Start Boot Log Capture'}
        </Button>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ borderRadius: '12px' }}>
          {error}
        </Alert>
      )}
    </Box>
  );
};

export default NewCaptureBootLog;
