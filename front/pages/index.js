import React from 'react';
import { useRouter } from 'next/router';
import { Typography, Box, AppBar, Toolbar, Avatar, Grid } from '@mui/material';

const Index = () => {
    const router = useRouter();

    return (
        <Box sx={{ 
            minHeight: '100vh', 
            bgcolor: 'background.default', 
            display: 'flex', 
            flexDirection: 'column',
        }}>
            
            {/* Header / AppBar - Glassmorphism Light */}
            <AppBar 
                position="fixed"
                sx={{
                    background: 'rgba(255, 255, 255, 0.75)',
                    boxShadow: '0 4px 30px rgba(0, 0, 0, 0.03)',
                    backdropFilter: 'blur(16px)',
                    WebkitBackdropFilter: 'blur(16px)',
                    borderBottom: '1px solid',
                    borderColor: 'divider',
                    width: '100%',
                    color: 'text.primary'
                }}
            >
                <Toolbar sx={{ padding: '8px 16px' }}>
                    <Avatar 
                        src="https://ece.iiita.ac.in/img/logo.png" 
                        alt="IIIT A" 
                        sx={{ width: '60px', height: '60px', marginRight: '16px', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)'}} 
                    />
                    <Typography variant="h3" component="div" sx={{ flexGrow: 1, fontSize: '1.2rem', letterSpacing: '-0.5px' }}>
                        IoT Security Research Lab, IIIT Allahabad
                    </Typography>
                    <Typography variant="body2" component="div" sx={{ 
                        border: '1px solid', 
                        borderColor: 'divider', 
                        borderRadius: '20px', 
                        padding: '6px 16px', 
                        backgroundColor: 'background.paper', 
                        fontWeight: 600,
                        color: 'text.secondary'
                    }}>
                        Hardware Auditing Tool
                    </Typography>
                    <Avatar 
                        src="https://pbs.twimg.com/profile_images/1805473337403228160/dloBXOi-_400x400.jpg" 
                        alt="C3i" 
                        sx={{ width: '60px', height: '60px', marginLeft: '16px', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)'}} 
                    />
                </Toolbar>
            </AppBar>

            {/* Main Content Area */}
            <Box sx={{ 
                flexGrow: 1, 
                display: 'flex', 
                flexDirection: 'column', 
                alignItems: 'center', 
                justifyContent: 'center',
                pt: 12,
                px: 3
            }}>
                <Typography variant="h1" sx={{ mb: 2, color: 'text.primary', textAlign: 'center', letterSpacing: '-1.5px' }}>
                    Hardware Auditing Tool
                </Typography>
                <Typography variant="body1" sx={{ color: 'text.secondary', mb: 8, maxWidth: '600px', textAlign: 'center' }}>
                    Select your hardware integration mode to begin auditing and analyzing IoT device security.
                </Typography>

                <Grid container spacing={4} sx={{ maxWidth: '900px', justifyContent: 'center' }}>
                    
                    {/* Relay Mode Button */}
                    <Grid item xs={12} sm={6}>
                        <Box 
                            onClick={() => router.push('/dashboard?mode=relay')} 
                            sx={{
                                background: 'background.paper',
                                borderRadius: '28px',
                                padding: '48px 32px',
                                textAlign: 'center',
                                cursor: 'pointer',
                                border: '1px solid',
                                borderColor: 'divider',
                                boxShadow: '0 10px 40px rgba(0,0,0,0.04)',
                                transition: 'all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1)',
                                '&:hover': {
                                    transform: 'translateY(-8px)',
                                    boxShadow: '0 20px 40px rgba(37, 99, 235, 0.1)',
                                    background: 'action.hover'
                                }
                            }}
                        >
                            <Typography variant="h2" sx={{ mb: 2, color: 'primary.main', letterSpacing: '-1px' }}>
                                Relay
                            </Typography>
                            <Typography variant="body1" sx={{ color: 'text.secondary' }}>
                                Legacy hardware integration mode. Access the standard Voltage Glitcher, Baudrate Detection, and Boot Log utilities.
                            </Typography>
                        </Box>
                    </Grid>

                    {/* OCTOCOPLOR Mode Button */}
                    <Grid item xs={12} sm={6}>
                        <Box 
                            onClick={() => router.push('/dashboard?mode=octocoplor')} 
                            sx={{
                                background: 'background.paper',
                                borderRadius: '28px',
                                padding: '48px 32px',
                                textAlign: 'center',
                                cursor: 'pointer',
                                border: '1px solid',
                                borderColor: 'divider',
                                boxShadow: '0 10px 40px rgba(0,0,0,0.04)',
                                transition: 'all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1)',
                                '&:hover': {
                                    transform: 'translateY(-8px)',
                                    boxShadow: '0 20px 40px rgba(245, 158, 11, 0.1)',
                                    background: 'action.hover'
                                }
                            }}
                        >
                            <Typography variant="h2" sx={{ mb: 2, color: 'secondary.main', letterSpacing: '-1px' }}>
                                OCTOCOPLOR
                            </Typography>
                            <Typography variant="body1" sx={{ color: 'text.secondary' }}>
                                New hardware integration mode. Access advanced UART analysis, new glitching methods, and updated bootlog parsing.
                            </Typography>
                        </Box>
                    </Grid>

                </Grid>
            </Box>
        </Box>
    );
};

export default Index;
