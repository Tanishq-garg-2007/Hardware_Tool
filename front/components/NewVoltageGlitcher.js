import React, { useRef, useState } from 'react';
import {
  Box,
  Button,
  TextField,
  Typography,
  Grid,
  Paper,
  Alert,
} from '@mui/material';
import { useRouter } from 'next/router';
import PowerSettingsNewIcon from '@mui/icons-material/PowerSettingsNew';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const NewVoltageGlitcher = ({ onBack }) => {
  const router = useRouter();
  const powerOnTimeRef = useRef();
  const powerOffTimeRef = useRef();
  const powerDurationTImeRef = useRef();
  const [status, setStatus] = useState(null);

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

  const powerOffHandler = async () => {
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/new_switch_power/0`);
      const data = await response.json();
      if (!response.ok || data.status === 'error') {
        throw new Error(data.message || 'Failed to switch power off.');
      }
      setStatus({ type: 'info', msg: data.message || 'Power Switched OFF (Octocoupler State 0)' });
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Failed to switch power off.' });
    }
  };

  const powerOnHandler = async () => {
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/new_switch_power/1`);
      const data = await response.json();
      if (!response.ok || data.status === 'error') {
        throw new Error(data.message || 'Failed to switch power on.');
      }
      setStatus({ type: 'success', msg: data.message || 'Power Switched ON (Octocoupler State 1)' });
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Failed to switch power on.' });
    }
  };

  const powerOnTimeHandler = async () => {
    const pon = powerOnTimeRef.current?.value?.trim() || '5';
    const poff = powerOffTimeRef.current?.value?.trim() || '3';
    const duration = powerDurationTImeRef.current?.value?.trim() || '10';
    if (!pon || !poff || !duration) return;
    try {
      const resp = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/new_set_volt_custom/${pon}/${poff}/${duration}`);
      const data = await resp.json();
      if (!resp.ok || data.status === 'error') {
        throw new Error(data.message || 'Failed to start advanced pulse glitching.');
      }
      setStatus({ type: 'success', msg: data.message || `Advanced pulse configured: ON=${pon}s, OFF=${poff}s, Duration=${duration}m.` });
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Failed to set advanced pulse timing.' });
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {status && (
        <Alert severity={status.type} onClose={() => setStatus(null)} sx={{ borderRadius: '12px' }}>
          {status.msg}
        </Alert>
      )}

      {/* Direct Power Switch */}
      <Paper variant="outlined" sx={{ p: 2.5, borderRadius: '16px', backgroundColor: 'background.default' }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <PowerSettingsNewIcon color="primary" /> Octocoupler Power Control
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <Button
            variant="contained"
            color="success"
            onClick={powerOnHandler}
            sx={{ borderRadius: '12px', fontWeight: 600, px: 3 }}
          >
            Turn On Power
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={powerOffHandler}
            sx={{ borderRadius: '12px', fontWeight: 600, px: 3 }}
          >
            Turn Off Power
          </Button>
        </Box>
      </Paper>

      {/* Custom Glitch Timing */}
      <Paper variant="outlined" sx={{ p: 2.5, borderRadius: '16px', backgroundColor: 'background.default' }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
          Advanced Pulse Timing & Duration
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={4}>
            <TextField
              fullWidth
              size="small"
              label="Power On Time (Sec)"
              placeholder="5"
              inputRef={powerOnTimeRef}
              type="number"
              variant="outlined"
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <TextField
              fullWidth
              size="small"
              label="Power Off Time (Sec)"
              placeholder="3"
              inputRef={powerOffTimeRef}
              type="number"
              variant="outlined"
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <TextField
              fullWidth
              size="small"
              label="Duration (Min)"
              placeholder="10"
              inputRef={powerDurationTImeRef}
              type="number"
              variant="outlined"
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
            />
          </Grid>
        </Grid>
        <Button
          variant="contained"
          onClick={powerOnTimeHandler}
          sx={{ mt: 2, borderRadius: '10px', fontWeight: 600 }}
        >
          Apply Advanced Timing
        </Button>
      </Paper>

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

export default NewVoltageGlitcher;
