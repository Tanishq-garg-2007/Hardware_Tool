import React, { useState } from 'react';
import { useRouter } from 'next/router';
import { Typography, Box, AppBar, Toolbar, Avatar, Grid, Button } from '@mui/material';
import ActionAreaCard from '../components/Card';

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

    const renderAnalysisComponent = () => {
        switch (showAnalysis) {
            case 1:
                return <FirmwareAnalysis />;
            case 2:
                return <FileAnalysisComponent />;
            case 3:
                return <CompleteAnalysisComponent />;
            case 4:
                return <HardCoded_Password />;
            default:
                return null;
        }
    };

    return (
        <Box sx={{ 
            minHeight: '100vh', 
            bgcolor: 'background.default', 
            display: 'flex', 
            flexDirection: 'column',
        }}>
            
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
                        Dashboard ({mode ? mode.toUpperCase() : 'General'})
                    </Typography>
                    <Avatar 
                        src="https://pbs.twimg.com/profile_images/1805473337403228160/dloBXOi-_400x400.jpg" 
                        alt="C3i" 
                        sx={{ width: '60px', height: '60px', marginLeft: '16px', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.05)'}} 
                    />
                </Toolbar>
            </AppBar>

            <Box sx={{ 
                flexGrow: 1, 
                display: 'flex', 
                flexDirection: 'column', 
                alignItems: 'center', 
                justifyContent: 'flex-start',
                pt: 15,
                px: 3
            }}>
                <Box sx={{ width: '100%', maxWidth: '1000px', display: 'flex', justifyContent: 'flex-start', mb: 2 }}>
                    <Button 
                        variant="text" 
                        onClick={() => router.push('/')}
                        sx={{ color: 'text.secondary', fontWeight: 500 }}
                    >
                        &larr; Back to Mode Selection
                    </Button>
                </Box>
                <Typography variant="h2" sx={{ mb: 4, color: 'text.primary', textAlign: 'center', letterSpacing: '-1px' }}>
                    Common Analysis Tools
                </Typography>

                {showAnalysis === 0 ? (
                    <Grid container spacing={4} sx={{ maxWidth: '1000px', justifyContent: 'center' }}>
                        
                        <Grid item xs={12} sm={6} md={4}>
                            <ActionAreaCard 
                                title="Firmware Analysis" 
                                description="Perform comprehensive firmware analysis." 
                                setCurrentModule={() => setShowAnalysis(1)} 
                            />
                        </Grid>
                        
                        <Grid item xs={12} sm={6} md={4}>
                            <ActionAreaCard 
                                title="File Analysis" 
                                description="Analyze specific files within the firmware." 
                                setCurrentModule={() => setShowAnalysis(2)} 
                            />
                        </Grid>
                        
                        <Grid item xs={12} sm={6} md={4}>
                            <ActionAreaCard 
                                title="Complete Analysis" 
                                description="Run a full suite of automated analysis tools." 
                                setCurrentModule={() => setShowAnalysis(3)} 
                            />
                        </Grid>

                        <Grid item xs={12} sm={6} md={4}>
                            <ActionAreaCard 
                                title="Hardcoded Passwords" 
                                description="Scan firmware for embedded credentials." 
                                setCurrentModule={() => setShowAnalysis(4)} 
                            />
                        </Grid>

                        <Grid item xs={12} sm={6} md={4}>
                            <ActionAreaCard 
                                title="SPI Tools" 
                                description="Access SPI related hardware tools." 
                                setCurrentModule={() => router.push('/spi')} 
                            />
                        </Grid>

                        <Grid item xs={12} sm={6} md={4}>
                            <Box 
                                onClick={() => router.push(`/uart?mode=${mode || 'relay'}`)} 
                                sx={{
                                    background: 'background.paper',
                                    borderRadius: '16px',
                                    padding: '24px',
                                    textAlign: 'center',
                                    cursor: 'pointer',
                                    border: '1px solid',
                                    borderColor: 'divider',
                                    boxShadow: '0 4px 20px rgba(0,0,0,0.02)',
                                    transition: 'all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1)',
                                    height: '100%',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    justifyContent: 'center',
                                    '&:hover': {
                                        transform: 'translateY(-4px)',
                                        boxShadow: '0 12px 30px rgba(0,0,0,0.06)',
                                        background: 'action.hover'
                                    }
                                }}
                            >
                                <Typography variant="h3" sx={{ mb: 1, color: 'primary.main' }}>
                                    UART Tools ({mode || 'relay'})
                                </Typography>
                                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                                    Access UART functionality specifically for {mode}.
                                </Typography>
                            </Box>
                        </Grid>

                    </Grid>
                ) : (
                    <Box sx={{ width: '100%', maxWidth: '1200px' }}>
                        <Button 
                            variant="outlined" 
                            onClick={() => setShowAnalysis(0)}
                            sx={{ mb: 3, borderRadius: '12px' }}
                        >
                            &larr; Back to Dashboard
                        </Button>
                        <Box sx={{ 
                            background: 'background.paper', 
                            borderRadius: '24px', 
                            p: 4,
                            boxShadow: '0 10px 40px rgba(0,0,0,0.04)',
                            border: '1px solid',
                            borderColor: 'divider'
                        }}>
                            {renderAnalysisComponent()}
                        </Box>
                    </Box>
                )}
            </Box>
        </Box>
    );
};

export default Dashboard;
