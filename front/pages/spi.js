import React from 'react';
import { useRouter } from 'next/router';
import { Box, AppBar, Toolbar, Avatar, Typography, Button } from '@mui/material';
import Forms from '@/components/Forms';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const SpiPage = () => {
    const router = useRouter();

    return (
        <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', display: 'flex', flexDirection: 'column' }}>
            {/* Top Navigation Header */}
            <AppBar 
                position="fixed"
                sx={{
                    background: 'rgba(255, 255, 255, 0.8)',
                    boxShadow: '0 4px 30px rgba(0, 0, 0, 0.03)',
                    backdropFilter: 'blur(16px)',
                    WebkitBackdropFilter: 'blur(16px)',
                    borderBottom: '1px solid',
                    borderColor: 'divider',
                    width: '100%',
                    color: 'text.primary',
                    zIndex: 1100,
                }}
            >
                <Toolbar sx={{ padding: '8px 24px' }}>
                    <Avatar 
                        src="https://ece.iiita.ac.in/img/logo.png" 
                        alt="IIIT A" 
                        sx={{ width: '50px', height: '50px', marginRight: '16px', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)' }} 
                    />
                    <Typography variant="h3" component="div" sx={{ flexGrow: 1, fontSize: '1.15rem', letterSpacing: '-0.5px' }}>
                        IoT Security Research Lab, IIIT Allahabad
                    </Typography>

                    <Typography variant="body2" component="div" sx={{ 
                        border: '1px solid', 
                        borderColor: 'divider', 
                        borderRadius: '20px', 
                        padding: '6px 16px', 
                        backgroundColor: 'background.paper', 
                        fontWeight: 600,
                        color: 'primary.main',
                        mr: 2
                    }}>
                        SPI Tools
                    </Typography>

                    <Avatar 
                        src="https://pbs.twimg.com/profile_images/1805473337403228160/dloBXOi-_400x400.jpg" 
                        alt="C3i" 
                        sx={{ width: '50px', height: '50px', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)' }} 
                    />
                </Toolbar>
            </AppBar>

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