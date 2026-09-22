import React, { useState } from 'react';
import { useRouter } from 'next/router';
import { Box, Grid, Button } from '@mui/material';
import Navbar from '@/components/Navbar';
import LeftPanelUART from '@/components/LeftPanelUART';
import RightPanelUART from '@/components/RightPanelUART';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const UartPage = () => {
    const [currentModule, setCurrentModule] = useState('none');
    const router = useRouter();
    const { mode } = router.query;
    const modeLabel = (mode || 'relay').toUpperCase();

    return (
        <Box sx={{ 
            minHeight: '100vh', 
            bgcolor: 'background.default', 
            display: 'flex',
            flexDirection: 'column',
        }}>
            {/* Top Navigation Header */}
            <Navbar 
                badgeText={`UART Mode: ${modeLabel}`} 
                badgeColor={mode === 'octocoplor' ? 'secondary.main' : 'primary.main'} 
            />

            {/* Main Content Area */}
            <Box sx={{ 
                flexGrow: 1, 
                pt: { xs: 12, md: 14 }, 
                pb: 6,
                px: { xs: 2, md: 4 },
                maxWidth: '1600px',
                width: '100%',
                margin: '0 auto',
            }}>
                <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Button 
                        startIcon={<ArrowBackIcon />}
                        onClick={() => router.push(`/dashboard?mode=${mode || 'relay'}`)}
                        sx={{ 
                            color: 'text.secondary', 
                            fontWeight: 600, 
                            borderRadius: '10px',
                            '&:hover': { color: 'text.primary', backgroundColor: 'action.hover' }
                        }}
                    >
                        Back to Dashboard
                    </Button>
                </Box>

                <Grid container spacing={3}>
                    <LeftPanelUART setCurrentModule={setCurrentModule} mode={mode} />
                    <RightPanelUART currentModule={currentModule} />
                </Grid>
            </Box>
        </Box>
    );
};

export default UartPage;
