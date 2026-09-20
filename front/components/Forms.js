import React, { useState } from 'react';
import { useRouter } from 'next/router';
import {
  Box,
  Button,
  TextField,
  Typography,
  Paper,
  CircularProgress,
  Switch,
  FormControlLabel,
  Alert,
  Chip,
  Grid,
  Divider,
  InputAdornment
} from '@mui/material';
import MemoryIcon from '@mui/icons-material/Memory';
import FlashOnIcon from '@mui/icons-material/FlashOn';
import PowerSettingsNewIcon from '@mui/icons-material/PowerSettingsNew';
import SaveIcon from '@mui/icons-material/Save';
import SpeedIcon from '@mui/icons-material/Speed';
import SearchIcon from '@mui/icons-material/Search';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ChecksumComparator from './ChecksumComparator';

const COMMON_CHIPS = ['MX25L12805D', 'W25Q128FV', 'W25Q64JV', 'GD25Q64', 'EN25F80', 'AT25DF641'];
const SPEED_PRESETS = [
  { label: '100 kHz (Safe/Slow)', value: '100' },
  { label: '2 MHz (Standard)', value: '2000' },
  { label: '8 MHz (Fast)', value: '8000' },
  { label: '16 MHz (High Speed)', value: '16000' }
];

const Forms = () => {
  const router = useRouter();
  const [spiSpeed, setSpiSpeed] = useState('');
  const [fileName, setFileName] = useState('');
  const [chip, setChip] = useState('');
  const [psuPower, setPsuPower] = useState(false);
  const [piPower, setPiPower] = useState(false);

  const [loadingExtract, setLoadingExtract] = useState(false);
  const [loadingChip, setLoadingChip] = useState(false);
  const [alertInfo, setAlertInfo] = useState(null); // { type: 'success' | 'error' | 'warning' | 'info', message: string }

  const extractFirmware = async () => {
    if (!chip.trim()) {
      setAlertInfo({
        type: 'warning',
        message: 'Please enter a target chip part number or click "Auto-Detect Chip" before extracting.'
      });
      return;
    }

    setLoadingExtract(true);
    setAlertInfo(null);

    const targetFileName = fileName.trim() || 'dump.bin';
    const targetSpeed = String(spiSpeed || '1000');

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/spi`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          spiSpeed: targetSpeed,
          chip: chip.trim(),
          fileName: targetFileName,
          psuPower: Boolean(psuPower),
          piPower: Boolean(piPower)
        })
      });

      const data = await response.json();

      if (data.success) {
        setAlertInfo({
          type: 'success',
          message: data.message || `Firmware extracted successfully and saved to ${targetFileName}!`
        });
      } else {
        setAlertInfo({
          type: 'error',
          message: data.message || 'Firmware extraction failed. Please check SPI wiring and power supply.'
        });
      }
    } catch (err) {
      setAlertInfo({
        type: 'error',
        message: `Network/Server Error: ${err.message}`
      });
    } finally {
      setLoadingExtract(false);
    }
  };

  const extractchipname = async () => {
    setLoadingChip(true);
    setAlertInfo(null);

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/chipname`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          spiSpeed: Number(spiSpeed) || 100
        })
      });

      const data = await response.json();

      if (data.success && data.chip) {
        setChip(data.chip);
        setAlertInfo({
          type: 'success',
          message: `SPI Flash Chip Identified: ${data.chip}`
        });
      } else {
        setAlertInfo({
          type: 'warning',
          message: data.message || 'Could not auto-detect flash chip. Please verify SPI connection (CS, CLK, MOSI, MISO, GND).'
        });
      }
    } catch (err) {
      setAlertInfo({
        type: 'error',
        message: `Chip Detection Error: ${err.message}`
      });
    } finally {
      setLoadingChip(false);
    }
  };

  return (
    <Box sx={{ maxWidth: '1000px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header Banner */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 1 }}>
        <Box>
          <Typography variant="h3" sx={{ fontWeight: 700, color: 'text.primary', letterSpacing: '-0.5px' }}>
            SPI Flash Extractor
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
            Direct SPI hardware memory readout, chip autodetection, and raw firmware image extraction.
          </Typography>
        </Box>
        <Chip
          icon={<MemoryIcon sx={{ fontSize: '16px !important' }} />}
          label="SPI Bus 0.0 & Flashrom"
          color="primary"
          variant="outlined"
          sx={{ borderRadius: '10px', fontWeight: 600 }}
        />
      </Box>

      {/* Inline Feedback Alerts */}
      {alertInfo && (
        <Alert
          severity={alertInfo.type}
          onClose={() => setAlertInfo(null)}
          sx={{ borderRadius: '12px', alignItems: 'flex-start' }}
        >
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {alertInfo.message}
          </Typography>
        </Alert>
      )}

      {/* Main Configuration Card */}
      <Paper
        variant="outlined"
        sx={{
          p: 3.5,
          borderRadius: '20px',
          backgroundColor: 'background.paper',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)',
          borderColor: 'divider',
          display: 'flex',
          flexDirection: 'column',
          gap: 3
        }}
      >
        {/* Section 1: Power & Bus Selection
        <Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
            <PowerSettingsNewIcon color="primary" /> Target Power Rail Selection
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  borderRadius: '14px',
                  backgroundColor: psuPower ? 'action.hover' : 'background.default',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}
              >
                <Box>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    External PSU Power
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    Power chip via bench power supply rail
                  </Typography>
                </Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={psuPower}
                      onChange={(e) => setPsuPower(e.target.checked)}
                      color="primary"
                    />
                  }
                  label=""
                  sx={{ m: 0 }}
                />
              </Paper>
            </Grid>

            <Grid item xs={12} sm={6}>
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  borderRadius: '14px',
                  backgroundColor: piPower ? 'action.hover' : 'background.default',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}
              >
                <Box>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    Raspberry Pi 3.3V Power
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    Power target through Pi header 3.3V pin
                  </Typography>
                </Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={piPower}
                      onChange={(e) => setPiPower(e.target.checked)}
                      color="primary"
                    />
                  }
                  label=""
                  sx={{ m: 0 }}
                />
              </Paper>
            </Grid>
          </Grid>
        </Box> */}

        {/* <Divider /> */}

        {/* Section 2: SPI Clock Speed */}
        <Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
            <SpeedIcon color="primary" /> SPI Bus Speed (kHz)
          </Typography>
          {/* <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
            {SPEED_PRESETS.map((preset) => (
              <Chip
                key={preset.value}
                label={preset.label}
                variant={spiSpeed === preset.value ? 'filled' : 'outlined'}
                color={spiSpeed === preset.value ? 'primary' : 'default'}
                onClick={() => setSpiSpeed(preset.value)}
                sx={{ borderRadius: '8px', cursor: 'pointer', fontWeight: 500 }}
              />
            ))}
          </Box> */}
          <TextField
            fullWidth
            size="small"
            placeholder='1000'
            type="number"
            value={spiSpeed}
            onChange={(e) => setSpiSpeed(e.target.value)}
            InputProps={{
              endAdornment: <InputAdornment position="end">kHz</InputAdornment>
            }}
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px', bgcolor: 'background.default' } }}
          />
        </Box>

        <Divider />

        {/* Section 3: Flash Chip & Auto-detection */}
        <Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
            <MemoryIcon color="primary" /> Flash Chip Identification
          </Typography>

          <Box sx={{ display: 'flex', gap: 1.5, mb: 2 }}>
            <TextField
              fullWidth
              size="small"
              label="Target Chip Name"
              value={chip}
              onChange={(e) => setChip(e.target.value)}
              placeholder="e.g. MX25L12805D, W25Q128FV"
              sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px', bgcolor: 'background.default' } }}
            />
            <Button
              variant="outlined"
              color="primary"
              onClick={extractchipname}
              disabled={loadingChip}
              startIcon={loadingChip ? <CircularProgress size={18} color="inherit" /> : <SearchIcon />}
              sx={{ borderRadius: '12px', whiteSpace: 'nowrap', px: 2.5, fontWeight: 600 }}
            >
              {loadingChip ? 'Detecting Chip...' : 'Auto-Detect Chip'}
            </Button>
          </Box>

          {/* Common Chips Quick Select */}
          {/* <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.8, alignItems: 'center' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', mr: 0.5 }}>
              Quick Select:
            </Typography>
            {COMMON_CHIPS.map((chipName) => (
              <Chip
                key={chipName}
                label={chipName}
                size="small"
                variant={chip === chipName ? 'filled' : 'outlined'}
                color={chip === chipName ? 'primary' : 'default'}
                onClick={() => setChip(chipName)}
                sx={{ borderRadius: '6px', fontSize: '11px', cursor: 'pointer' }}
              />
            ))}
          </Box> */}
        </Box>

        <Divider />

        {/* Section 4: Firmware Output Filename & Extraction */}
        <Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
            <SaveIcon color="primary" /> Destination Image Filename
          </Typography>

          <TextField
            fullWidth
            size="small"
            value={fileName}
            onChange={(e) => setFileName(e.target.value)}
            placeholder="dump.bin"
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px', bgcolor: 'background.default' }, mb: 3 }}
          />

          {/* Action Button */}
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Button
              variant="contained"
              size="large"
              onClick={extractFirmware}
              disabled={loadingExtract}
              startIcon={loadingExtract ? <CircularProgress size={20} color="inherit" /> : <FlashOnIcon />}
              sx={{
                borderRadius: '12px',
                py: 1.4,
                px: 4,
                fontWeight: 700,
                fontSize: '15px',
                color: '#FFFFFF !important',
                backgroundColor: '#2563EB',
                backgroundImage: 'linear-gradient(135deg, #2563EB 0%, #1D4ED8 100%)',
                boxShadow: '0 4px 14px rgba(37, 99, 235, 0.35)',
                transition: 'all 0.2s ease-in-out',
                '&:hover': {
                  backgroundColor: '#1D4ED8',
                  backgroundImage: 'linear-gradient(135deg, #1D4ED8 0%, #1E40AF 100%)',
                  boxShadow: '0 6px 20px rgba(37, 99, 235, 0.45)',
                  transform: 'translateY(-1px)',
                },
                '&:active': {
                  transform: 'translateY(0)',
                },
                '&.Mui-disabled': {
                  color: '#FFFFFF !important',
                  opacity: 0.75,
                  backgroundImage: 'linear-gradient(135deg, #60A5FA 0%, #3B82F6 100%)',
                  backgroundColor: '#3B82F6',
                }
              }}
            >
              {loadingExtract ? 'Extracting SPI Flash Memory...' : 'Extract Firmware Image'}
            </Button>
          </Box>
        </Box>
      </Paper>

      {/* Binary Checksum & Integrity Comparator */}
      <ChecksumComparator />

      {/* Bottom Back Navigation */}
      <Box sx={{ display: 'flex', justifyContent: 'flex-start', mt: 1.5 }}>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => router.push('/dashboard')}
          sx={{
            color: 'text.secondary',
            fontWeight: 600,
            borderRadius: '10px',
            py: 0.8,
            px: 1.5,
            '&:hover': { color: 'text.primary', backgroundColor: 'action.hover' }
          }}
        >
          Back to Dashboard
        </Button>
      </Box>
    </Box>
  );
};

export default Forms;
