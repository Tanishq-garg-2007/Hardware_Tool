import React, { useState } from 'react';
import { useRouter } from 'next/router';
import {
  Typography,
  Box,
  Grid,
  Button,
  Chip,
  Paper,
  TextField,
  InputAdornment,
  Divider,
} from '@mui/material';
import Navbar from '@/components/Navbar';
import ActionAreaCard from '../components/Card';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import SearchIcon from '@mui/icons-material/Search';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';

// Import all common analysis components
import FirmwareAnalysis from "../components/FirmwareAnalysis";
import FileAnalysisComponent from "../components/FileAnalysisComponent";
import CompleteAnalysisComponent from "../components/CompleteAnalysisComponent";
import HardCoded_Password from "../components/HardCoded_Password";
import FolderMenu from "../components/FolderMenu";

const Dashboard = () => {
  const router = useRouter();
  const { mode } = router.query;
  const [showAnalysis, setShowAnalysis] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState('All');

  const tools = [
    {
      id: 1,
      title: 'Firmware Analysis',
      category: 'Firmware & Binary',
      description: 'Comprehensive firmware unpacking, header analysis, entropy mapping, and filesystem triage.',
      onClick: () => setShowAnalysis(1),
    },
    {
      id: 2,
      title: 'File Analysis',
      category: 'Firmware & Binary',
      description: 'Analyze specific extracted files, ELF headers, library dependencies, and embedded strings.',
      onClick: () => setShowAnalysis(2),
    },
    {
      id: 3,
      title: 'Complete Analysis',
      category: 'Firmware & Binary',
      description: 'Execute an end-to-end automated security pipeline across firmware with structured risk reports.',
      onClick: () => setShowAnalysis(3),
    },
    {
      id: 4,
      title: 'Hardcoded Passwords',
      category: 'Hardware & Exploitation',
      description: 'Scan unpacked root filesystems for shadow hashes, private keys, API credentials, and tokens.',
      onClick: () => setShowAnalysis(4),
    },
    {
      id: 5,
      title: 'SPI Tools',
      category: 'Hardware & Exploitation',
      description: 'Direct SPI bus clock tuning, chip autodetection, and full physical flash memory extraction.',
      onClick: () => router.push('/spi'),
    },
    {
      id: 6,
      title: `UART COMMUNICATION (${mode || 'relay'})`,
      category: 'Hardware & Exploitation',
      description: 'Serial console monitoring, baudrate detection, voltage glitching, and bootlog CVE scanner.',
      onClick: () => router.push(`/uart?mode=${mode || 'relay'}`),
    },
  ];

  const filteredTools = tools.filter((tool) => {
    const matchesCategory = activeCategory === 'All' || tool.category === activeCategory;
    const query = searchQuery.toLowerCase().trim();
    const matchesQuery =
      !query ||
      tool.title.toLowerCase().includes(query) ||
      tool.description.toLowerCase().includes(query);
    return matchesCategory && matchesQuery;
  });

  const handleCloseAnalysis = () => {
    setShowAnalysis(0);
  };

  const renderAnalysisComponent = () => {
    switch (showAnalysis) {
      case 1:
        return <FirmwareAnalysis onBack={handleCloseAnalysis} />;
      case 2:
        return <FileAnalysisComponent onBack={handleCloseAnalysis} />;
      case 3:
        return <CompleteAnalysisComponent onBack={handleCloseAnalysis} />;
      case 4:
        return <HardCoded_Password onBack={handleCloseAnalysis} />;
      default:
        return null;
    }
  };

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation Header */}
      <Navbar
        badgeText={mode ? `Mode: ${mode.toUpperCase()}` : 'Hardware Auditing Tool'}
        badgeColor={mode === 'octocoplor' ? 'secondary.main' : 'primary.main'}
      />

      {/* Main Container */}
      <Box
        sx={{
          flexGrow: 1,
          pt: { xs: 12, md: 14 },
          pb: 8,
          px: { xs: 2, sm: 3, md: 4 },
          maxWidth: '1200px',
          width: '100%',
          margin: '0 auto',
        }}
      >
        {showAnalysis === 0 ? (
          <>
            {/* Top Navigation Row */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3, flexWrap: 'wrap', gap: 1 }}>
              <Button
                startIcon={<ArrowBackIcon />}
                onClick={() => router.push('/')}
                sx={{
                  color: 'text.secondary',
                  fontWeight: 600,
                  borderRadius: '10px',
                  py: 0.8,
                  px: 1.5,
                  '&:hover': { color: 'text.primary', backgroundColor: 'action.hover' },
                }}
              >
                Back to Mode Selection
              </Button>

              {/* <Chip
                icon={<CheckCircleOutlineIcon sx={{ fontSize: '16px !important', color: 'success.main' }} />}
                label="Hardware Platform Ready"
                variant="outlined"
                size="small"
                sx={{ fontWeight: 600, borderRadius: '8px', color: 'text.secondary', borderColor: 'divider' }}
              /> */}
            </Box>

            {/* Hero Header */}
            <Box sx={{ textAlign: 'center', mb: 4 }}>
              <Typography
                variant="h2"
                sx={{
                  fontWeight: 800,
                  color: 'text.primary',
                  letterSpacing: '-1.2px',
                  fontSize: { xs: '28px', sm: '36px' },
                  mb: 1.2,
                }}
              >
                Common Analysis Tools
              </Typography>
              <Typography
                variant="body1"
                sx={{
                  color: 'text.secondary',
                  maxWidth: '680px',
                  margin: '0 auto',
                  fontSize: { xs: '14px', sm: '15px' },
                  lineHeight: 1.6,
                }}
              >
                Select a specialized analysis suite to extract firmware, inspect filesystem structures, audit embedded
                secrets, or interface directly with hardware buses.
              </Typography>
            </Box>

            {/* Filter & Search Bar */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3.5, flexWrap: 'wrap', gap: 2 }}>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {['All', 'Firmware & Binary', 'Hardware & Exploitation'].map((cat) => (
                  <Chip
                    key={cat}
                    label={cat === 'All' ? 'All Suites (6)' : cat}
                    clickable
                    variant={activeCategory === cat ? 'filled' : 'outlined'}
                    color={activeCategory === cat ? 'primary' : 'default'}
                    onClick={() => setActiveCategory(cat)}
                    sx={{ borderRadius: '10px', fontWeight: 600, height: '32px' }}
                  />
                ))}
              </Box>

              <TextField
                size="small"
                placeholder="Search tools or keywords..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ color: 'text.secondary', fontSize: 20 }} />
                    </InputAdornment>
                  ),
                }}
                sx={{
                  width: { xs: '100%', sm: '260px' },
                  '& .MuiOutlinedInput-root': {
                    borderRadius: '12px',
                    backgroundColor: 'background.paper',
                  },
                }}
              />
            </Box>

            {/* Grid of Tool Cards */}
            <Grid container spacing={3} sx={{ maxWidth: '1000px', mx: 'auto', mt: 1 }}>
              {filteredTools.map((tool) => (
                <Grid item xs={12} sm={6} md={4} key={tool.id}>
                  <ActionAreaCard
                    title={tool.title}
                    setCurrentModule={tool.onClick}
                  />
                </Grid>
              ))}
            </Grid>

            {/* Bottom Back Button */}
            <Box sx={{ maxWidth: '1000px', mx: 'auto', mt: 4, display: 'flex', justifyContent: 'flex-start' }}>
              <Button
                startIcon={<ArrowBackIcon />}
                onClick={() => router.push('/')}
                sx={{
                  color: 'text.secondary',
                  fontWeight: 600,
                  borderRadius: '10px',
                  py: 0.8,
                  px: 1.5,
                  '&:hover': { color: 'text.primary', backgroundColor: 'action.hover' },
                }}
              >
                Back to Mode Selection
              </Button>
            </Box>
          </>
        ) : (
          /* Active Analysis Suite View */
          <Box sx={{ width: '100%' }}>
            <Box sx={{ mb: 3 }}>
              <Button
                startIcon={<ArrowBackIcon />}
                onClick={() => setShowAnalysis(0)}
                sx={{
                  color: 'text.secondary',
                  fontWeight: 600,
                  borderRadius: '10px',
                  py: 0.8,
                  px: 1.5,
                  '&:hover': { color: 'text.primary', backgroundColor: 'action.hover' },
                }}
              >
                Back to Tools Dashboard
              </Button>
            </Box>

            <Paper
              variant="outlined"
              sx={{
                background: 'background.paper',
                borderRadius: '24px',
                p: { xs: 2.5, sm: 3.5, md: 4.5 },
                boxShadow: '0 10px 40px rgba(0,0,0,0.03)',
                borderColor: 'divider',
              }}
            >
              {renderAnalysisComponent()}
            </Paper>

            {/* Bottom Back Button in Analysis Suite View */}
            <Box sx={{ mt: 3 }}>
              <Button
                startIcon={<ArrowBackIcon />}
                onClick={() => setShowAnalysis(0)}
                sx={{
                  color: 'text.secondary',
                  fontWeight: 600,
                  borderRadius: '10px',
                  py: 0.8,
                  px: 1.5,
                  '&:hover': { color: 'text.primary', backgroundColor: 'action.hover' },
                }}
              >
                Back to Tools Dashboard
              </Button>
            </Box>
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default Dashboard;
