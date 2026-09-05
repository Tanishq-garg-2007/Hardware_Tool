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
import PowerSettingsNewIcon from '@mui/icons-material/PowerSettingsNew';
import ElectricBoltIcon from '@mui/icons-material/ElectricBolt';
import TuneIcon from '@mui/icons-material/Tune';

const NewVoltageGlitcher = () => {
  const channelRef = useRef(null);
  const powerOnTimeRef = useRef();
  const powerOffTimeRef = useRef();
  const powerDurationTImeRef = useRef();
  const [freq, setFreq] = useState('');
  const [status, setStatus] = useState(null);

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

  const freqHandler = async () => {
    if (!freq) return;
    try {
      const resp = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/set_volt/${freq}`);
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
      const resp = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/set_channel/${channel}`);
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
    const pon = powerOnTimeRef.current?.value;
    const poff = powerOffTimeRef.current?.value;
    const duration = powerDurationTImeRef.current?.value;
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

      {/* Frequency & Channel */}
      <Grid container spacing={2}>
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
      </Grid>

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
    </Box>
  );
};

export default NewVoltageGlitcher;
