import React, { useState } from 'react';
import { useRouter } from 'next/router';
import { AppBar, Toolbar, Avatar, Typography } from '@mui/material';

export default function Navbar({
  badgeText = '',
  badgeColor = 'primary.main',
}) {
  const router = useRouter();
  const [iiitaSrc, setIiitaSrc] = useState('/images/iiita_logo.png');
  const [c3iSrc, setC3iSrc] = useState('/images/c3i_hub.png');

  return (
    <AppBar
      position="fixed"
      sx={{
        background: 'rgba(255, 255, 255, 0.85)',
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
      <Toolbar sx={{ padding: { xs: '8px 16px', sm: '8px 24px' } }}>
        <Avatar
          src={iiitaSrc}
          alt="IIIT Allahabad"
          onClick={() => router.push('/')}
          imgProps={{
            onError: () => setIiitaSrc('https://ece.iiita.ac.in/img/logo.png'),
          }}
          sx={{
            width: { xs: '44px', sm: '50px' },
            height: { xs: '44px', sm: '50px' },
            marginRight: { xs: '12px', sm: '16px' },
            borderRadius: '8px',
            boxShadow: '0 2px 10px rgba(0,0,0,0.05)',
            cursor: 'pointer',
            backgroundColor: '#FFFFFF',
          }}
        />

        <Typography
          variant="h3"
          component="div"
          onClick={() => router.push('/')}
          sx={{
            flexGrow: 1,
            fontSize: { xs: '0.95rem', sm: '1.15rem' },
            letterSpacing: '-0.5px',
            cursor: 'pointer',
            userSelect: 'none',
          }}
        >
          IoT Security Research Lab, IIIT Allahabad
        </Typography>

        {badgeText && (
          <Typography
            variant="body2"
            component="div"
            sx={{
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: '20px',
              padding: '6px 16px',
              backgroundColor: 'background.paper',
              fontWeight: 600,
              color: badgeColor,
              mr: 2,
              display: { xs: 'none', md: 'block' },
            }}
          >
            {badgeText}
          </Typography>
        )}

        <Avatar
          src={c3iSrc}
          alt="C3i Hub"
          imgProps={{
            onError: () => setC3iSrc('https://pbs.twimg.com/profile_images/1805473337403228160/dloBXOi-_400x400.jpg'),
          }}
          sx={{
            width: { xs: '44px', sm: '50px' },
            height: { xs: '44px', sm: '50px' },
            borderRadius: '8px',
            boxShadow: '0 2px 10px rgba(0,0,0,0.05)',
            backgroundColor: '#060513',
          }}
        />
      </Toolbar>
    </AppBar>
  );
}
