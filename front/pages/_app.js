import * as React from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import Head from 'next/head';
import "@/styles/globals.css";
import dynamic from 'next/dynamic';

const ChatBot = dynamic(() => import('@/components/ChatBot'), { ssr: false });

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
    MuiCssBaseline: {
      styleOverrides: {
        'input[type=number]::-webkit-outer-spin-button, input[type=number]::-webkit-inner-spin-button': {
          WebkitAppearance: 'none',
          margin: 0,
        },
        'input[type=number]': {
          MozAppearance: 'textfield',
          appearance: 'textfield',
        },
      },
    },
    MuiInputBase: {
      styleOverrides: {
        input: {
          '&[type=number]': {
            MozAppearance: 'textfield',
            appearance: 'textfield',
            '&::-webkit-outer-spin-button, &::-webkit-inner-spin-button': {
              WebkitAppearance: 'none',
              margin: 0,
            },
          },
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