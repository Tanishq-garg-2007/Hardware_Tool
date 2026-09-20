import * as React from 'react'
import Button from '@mui/material/Button'

export default function ActionAreaCard({
  title,
  setCurrentModule,
}) {
  return (
    <Button
      fullWidth
      variant="contained"
      onClick={() => setCurrentModule && setCurrentModule(title)}
      sx={{
        backgroundColor: '#1976D2',
        color: '#FFFFFF',
        py: 1.6,
        px: 3,
        borderRadius: '6px',
        fontWeight: 600,
        fontSize: '0.88rem',
        letterSpacing: '0.6px',
        textTransform: 'uppercase',
        boxShadow: '0 2px 4px -1px rgba(0,0,0,0.2), 0 4px 5px 0 rgba(0,0,0,0.14), 0 1px 10px 0 rgba(0,0,0,0.12)',
        transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        minHeight: '48px',
        width: '100%',
        '&:hover': {
          backgroundColor: '#1565C0',
          boxShadow: '0 4px 8px -1px rgba(0,0,0,0.2), 0 6px 10px 0 rgba(0,0,0,0.14), 0 1px 18px 0 rgba(0,0,0,0.12)',
          transform: 'translateY(-2px)',
        },
        '&:active': {
          transform: 'translateY(0)',
          boxShadow: '0 2px 4px -1px rgba(0,0,0,0.2)',
        },
      }}
    >
      {title}
    </Button>
  )
}
