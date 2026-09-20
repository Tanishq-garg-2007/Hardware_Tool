import React, { useRef, useState } from 'react';
import {
  Box,
  Button,
  TextField,
  Typography,
  Grid,
  Paper,
  Divider,
  Alert,
} from '@mui/material';
import { useRouter } from 'next/router';
import PowerSettingsNewIcon from '@mui/icons-material/PowerSettingsNew';
import ElectricBoltIcon from '@mui/icons-material/ElectricBolt';
import TuneIcon from '@mui/icons-material/Tune';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const VoltageGlitcher = ({ onBack }) => {
  const router = useRouter();
  const channelRef = useRef(null);
  const powerOnTimeRef = useRef();
  const powerOffTimeRef = useRef();
  const [freq, setFreq] = useState('');
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

  const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

  const powerOffHandler = async () => {
    try {
      const response = await fetch(`${apiBase}/switch_power/0`);
      const data = await response.json();
      if (!response.ok || data.status === 'error') {
        throw new Error(data.message || 'Failed to switch power off.');
      }
      setStatus({ type: 'info', msg: data.message || 'Power Switched OFF (Relay State 0)' });
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Failed to switch power off.' });
    }
  };

  const powerOnHandler = async () => {
    try {
      const response = await fetch(`${apiBase}/switch_power/1`);
      const data = await response.json();
      if (!response.ok || data.status === 'error') {
        throw new Error(data.message || 'Failed to switch power on.');
      }
      setStatus({ type: 'success', msg: data.message || 'Power Switched ON (Relay State 1)' });
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Failed to switch power on.' });
    }
  };

  const freqHandler = async () => {
    if (!freq) return;
    try {
      const resp = await fetch(`${apiBase}/set_volt/${freq}`);
      const data = await resp.json();
      if (!resp.ok || data.status === 'error') {
        throw new Error(data.message || 'Failed to set frequency.');
      }
      setStatus({ type: 'success', msg: data.message || `Frequency set to ${freq} Hz successfully.` });
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Failed to set frequency.' });
    }
  };

  const channelHandler = async () => {
    const channel = channelRef.current?.value;
    if (!channel) return;
    try {
      const resp = await fetch(`${apiBase}/set_channel/${channel}`);
      const data = await resp.json();
      if (!resp.ok || data.status === 'error') {
        throw new Error(data.message || 'Failed to set channel.');
      }
      setStatus({ type: 'success', msg: data.message || `Channel set to ${channel} successfully.` });
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Failed to set channel.' });
    }
  };

  const powerOnTimeHandler = async () => {
    const pon = powerOnTimeRef.current?.value?.trim() || '1';
    const poff = powerOffTimeRef.current?.value?.trim() || '0.5';
    if (!pon || !poff) return;
    try {
      const resp = await fetch(`${apiBase}/set_volt_custom/${pon}/${poff}`);
      const data = await resp.json();
      if (!resp.ok || data.status === 'error') {
        throw new Error(data.message || 'Failed to set custom pulse parameters.');
      }
      setStatus({ type: 'success', msg: data.message || `Custom voltage pulse applied: ON=${pon}ms, OFF=${poff}ms.` });
    } catch (e) {
      setStatus({ type: 'error', msg: e.message || 'Failed to set custom pulse parameters.' });
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
          <PowerSettingsNewIcon color="primary" /> Direct Power Control
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

      {/* Frequency & Channel */}
     {/* <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <Paper variant="outlined" sx={{ p: 2.5, borderRadius: '16px', backgroundColor: 'background.default', height: '100%' }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <ElectricBoltIcon color="primary" /> Frequency Tuning
            </Typography>
            <Box sx={{ display: 'flex', gap: 1.5 }}>
              <TextField
                fullWidth
                size="small"
                label="Frequency (Hz)"
                variant="outlined"
                value={freq}
                onChange={(e) => setFreq(e.target.value)}
                sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
              />
              <Button variant="contained" onClick={freqHandler} sx={{ borderRadius: '10px', fontWeight: 600 }}>
                Set
              </Button>
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper variant="outlined" sx={{ p: 2.5, borderRadius: '16px', backgroundColor: 'background.default', height: '100%' }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <TuneIcon color="primary" /> Channel Selection
            </Typography>
            <Box sx={{ display: 'flex', gap: 1.5 }}>
              <TextField
                fullWidth
                size="small"
                label="Channel"
                inputRef={channelRef}
                variant="outlined"
                sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
              />
              <Button variant="contained" onClick={channelHandler} sx={{ borderRadius: '10px', fontWeight: 600 }}>
                Set
              </Button>
            </Box>
          </Paper>
        </Grid>
      </Grid> */}

      {/* Custom Glitch Timing */}
      <Paper variant="outlined" sx={{ p: 2.5, borderRadius: '16px', backgroundColor: 'background.default' }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
          Custom Glitch Pulse Timing
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              size="small"
              label="Power On Time (Seconds)"
              placeholder="1"
              inputRef={powerOnTimeRef}
              type="number"
              variant="outlined"
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: '10px', backgroundColor: 'background.paper' } }}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              size="small"
              label="Power Off Time (Seconds)"
              placeholder="0.5"
              inputRef={powerOffTimeRef}
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
          Apply Custom Pulse Timing
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

export default VoltageGlitcher;
