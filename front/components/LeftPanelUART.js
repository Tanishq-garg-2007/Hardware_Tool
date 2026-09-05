import { Grid, Button, Box, Typography } from '@mui/material';
import React from 'react';
import ActionAreaCard from './Card';
import { useRouter } from 'next/router';

const LeftPanelUART = ({ setCurrentModule, mode }) => {
    const router = useRouter();
    
    const handleBackButtonClick = () => {
        router.push(`/dashboard?mode=${mode || 'relay'}`);
    };
    
    const isRelay = mode === 'relay';
    const isOctocoplor = mode === 'octocoplor';

    return (
        <Grid item xs={12} md={4} lg={3} sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            
            <Box sx={{ 
                background: 'background.paper', 
                backdropFilter: 'blur(16px)', 
                borderRadius: '24px', 
                padding: '24px', 
                width: '100%',
                boxShadow: '0 4px 30px rgba(0, 0, 0, 0.03)',
                border: '1px solid',
                borderColor: 'divider',
            }}>
                <Typography variant="h3" sx={{ mb: 3, color: 'text.primary', textAlign: 'center' }}>
                    {isRelay ? 'Relay Tools' : isOctocoplor ? 'OCTOCOPLOR Tools' : 'Hardware Tools'}
                </Typography>

                <Grid container direction="column" spacing={2}>
                    
                    {/* RELAY / OLD CODE MODULES */}
                    {isRelay && (
                        <>
                            <Grid item>
                                <ActionAreaCard
                                    title='Voltage Glitcher'
                                    description='Legacy voltage glitcher module.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                            <Grid item>
                                <ActionAreaCard
                                    title='Detect Baudrate'
                                    description='Legacy baudrate detection.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                            <Grid item>
                                <ActionAreaCard
                                    title='Check For UART Console'
                                    description='Legacy UART console check.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                            <Grid item>
                                <ActionAreaCard
                                    title='Capture Boot Logs'
                                    description='Legacy boot log capturing.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                            <Grid item>
                                <ActionAreaCard
                                    title='Analyze Boot Logs'
                                    description='Automated boot log CVE risk analysis.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                        </>
                    )}

                    {/* OCTOCOPLOR / NEW CODE MODULES */}
                    {isOctocoplor && (
                        <>
                            <Grid item>
                                <ActionAreaCard
                                    title='New Voltage Glitcher'
                                    description='Advanced voltage glitcher tool.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                            <Grid item>
                                <ActionAreaCard
                                    title='New Check for UART Analysis'
                                    description='Advanced UART analysis.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                            <Grid item>
                                <ActionAreaCard
                                    title='New Detect Baudrate'
                                    description='Advanced baudrate detection.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                            <Grid item>
                                <ActionAreaCard
                                    title='New Capture BootLog'
                                    description='Advanced boot log capturing.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                            <Grid item>
                                <ActionAreaCard
                                    title='Analyze Boot Logs'
                                    description='Automated boot log CVE risk analysis.'
                                    setCurrentModule={setCurrentModule}
                                />
                            </Grid>
                        </>
                    )}
                    
                    {/* Fallback if mode is undefined */}
                    {!isRelay && !isOctocoplor && (
                        <Grid item>
                            <Typography variant="body2" sx={{ color: 'text.secondary', textAlign: 'center' }}>
                                Please select a mode from the Home page.
                            </Typography>
                        </Grid>
                    )}

                    <Grid item sx={{ mt: 3 }}>
                        <Button 
                            variant="outlined" 
                            onClick={handleBackButtonClick} 
                            fullWidth
                            sx={{ 
                                borderRadius: '12px', 
                                padding: '10px',
                                borderColor: 'divider',
                                color: 'text.primary',
                                '&:hover': {
                                    backgroundColor: 'action.hover',
                                    borderColor: 'text.primary'
                                }
                            }}
                        >
                            Back To Home
                        </Button>
                    </Grid>
                </Grid>
            </Box>
        </Grid>
    );
}

export default LeftPanelUART;
