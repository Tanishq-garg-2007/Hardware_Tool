import * as React from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import Head from 'next/head';
import "@/styles/globals.css";
import ChatBot from '@/components/ChatBot';

const theme = createTheme({
  palette: {
    background: {
      default: '#F8FAFC', // Crisp modern slate-50 background
      paper: '#FFFFFF',   // Pure white cards and surfaces
    },
    primary: {
      main: '#2563EB', // Primary Blue
      light: '#3B82F6',
      dark: '#1D4ED8',
      contrastText: '#FFFFFF',
    },
    secondary: {
      main: '#D97706', // Warm Amber
      light: '#F59E0B',
      dark: '#B45309',
      contrastText: '#FFFFFF',
    },
    text: {
      primary: '#0F172A', // Deep Slate
      secondary: '#64748B', // Muted Slate
    },
    divider: '#E2E8F0',
    success: {
      main: '#10B981',
      light: '#D1FAE5',
      dark: '#047857',
    },
    error: {
      main: '#EF4444',
      light: '#FEE2E2',
      dark: '#B91C1C',
    },
    action: {
      hover: '#F1F5F9',
    },
  },
  shape: {
    borderRadius: 12,
  },
  typography: {
    fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    h1: {
      fontFamily: '"Montserrat", sans-serif',
      fontWeight: 700,
      fontSize: '44px',
      letterSpacing: '-1.5px',
    },
    h2: {
      fontFamily: '"Montserrat", sans-serif',
      fontWeight: 600,
      fontSize: '32px',
      letterSpacing: '-1px',
    },
    h3: {
      fontFamily: '"Montserrat", sans-serif',
      fontWeight: 600,
      fontSize: '22px',
      letterSpacing: '-0.5px',
    },
    h4: {
      fontFamily: '"Montserrat", sans-serif',
      fontWeight: 600,
      fontSize: '18px',
    },
    body1: {
      fontSize: '15px',
      lineHeight: 1.6,
      color: '#334155',
    },
    body2: {
      fontSize: '13.5px',
      lineHeight: 1.5,
      color: '#64748B',
    },
    button: {
      fontFamily: '"Inter", sans-serif',
      fontWeight: 600,
      fontSize: '14px',
      textTransform: 'none',
    },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: '10px',
          padding: '8px 18px',
          transition: 'all 0.2s ease-in-out',
        },
        containedPrimary: {
          boxShadow: '0 2px 8px rgba(37, 99, 235, 0.25)',
          '&:hover': {
            boxShadow: '0 4px 14px rgba(37, 99, 235, 0.35)',
            transform: 'translateY(-1px)',
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: '16px',
        },
      },
    },
  },
});

function App({ Component, pageProps }) {
  return (
    <>
      <Head>
        <title>IoT Security Research Lab | Hardware Auditing Tool</title>
        <meta name="description" content="Hardware Security Auditing, Bootlog CVE Extraction & Glitch Testing" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="true" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Montserrat:wght@600;700&display=swap"
          rel="stylesheet"
        />
      </Head>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Component {...pageProps} />
        <ChatBot />
      </ThemeProvider>
    </>
  );
}

export default App;