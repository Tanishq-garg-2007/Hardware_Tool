import * as React from 'react'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Typography from '@mui/material/Typography'
import { CardActionArea } from '@mui/material'

export default function ActionAreaCard({title, description, setCurrentModule}) {
  return (
    <Card
      sx={{ 
        maxWidth: 345, 
        backgroundColor: 'background.paper',
        backdropFilter: 'blur(10px)',
        color: 'text.primary',
        borderRadius: '16px',
        border: '1px solid',
        borderColor: 'divider',
        boxShadow: '0 4px 20px rgba(0,0,0,0.02)',
        transition: 'all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1)',
        height: '100%',
        '&:hover': {
            transform: 'translateY(-4px)',
            boxShadow: '0 12px 30px rgba(0,0,0,0.06)',
            backgroundColor: 'action.hover'
        }
      }}
      onClick={() => setCurrentModule(title)}
    >
      <CardActionArea sx={{ p: 1, height: '100%' }}>
        <CardContent>
          <Typography gutterBottom variant='h3' component='div' sx={{ mb: 1 }}>
            {title}
          </Typography>
          <Typography variant='body2' sx={{ color: 'text.secondary' }}>
            {description}
          </Typography>
        </CardContent>
      </CardActionArea>
    </Card>
  )
}
