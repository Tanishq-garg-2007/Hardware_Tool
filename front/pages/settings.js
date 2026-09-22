import FileUpload from '@/components/FileUpload';
import React from 'react';
import { Box } from '@mui/material';
import Navbar from '@/components/Navbar';

const Settings = () => {
  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', display: 'flex', flexDirection: 'column' }}>
      <Navbar badgeText="Settings" />
      <Box sx={{ pt: { xs: 12, md: 14 }, px: { xs: 2, md: 4 } }}>
        <FileUpload />
      </Box>
    </Box>
  );
};

export default Settings;