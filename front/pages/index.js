import React from 'react';
import { useRouter } from 'next/router';
import { Typography, Box, Grid } from '@mui/material';
import Navbar from '@/components/Navbar';

const Index = () => {
    const router = useRouter();

    return (
        <Box sx={{
            minHeight: '100vh',
            bgcolor: 'background.default',
            display: 'flex',
            flexDirection: 'column',
        }}>
            <Navbar badgeText="Hardware Auditing Tool" badgeColor="text.secondary" />

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
                        </Box>
                    </Grid>

                </Grid>
            </Box>
        </Box>
    );
};

export default Index;
