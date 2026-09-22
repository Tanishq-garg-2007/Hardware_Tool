import React from 'react';
import { useRouter } from 'next/router';
import { Box, Button } from '@mui/material';
import Navbar from '@/components/Navbar';
import Forms from '@/components/Forms';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const SpiPage = () => {
    const router = useRouter();

    return (
        <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', display: 'flex', flexDirection: 'column' }}>
            {/* Top Navigation Header */}
            <Navbar badgeText="SPI Tools" />

            {/* Content */}
            <Box sx={{ 
                flexGrow: 1, 
                pt: { xs: 12, md: 14 }, 
                pb: 6,
                px: { xs: 2, md: 4 },
                maxWidth: '1200px',
                width: '100%',
                margin: '0 auto',
            }}>
                <Box sx={{ mb: 3 }}>
                    <Button 
                        startIcon={<ArrowBackIcon />}
                        onClick={() => router.push('/dashboard')}
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

                <Forms />
            </Box>
        </Box>
    );
};

export default SpiPage;