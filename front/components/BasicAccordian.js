import * as React from 'react'
import Accordion from '@mui/material/Accordion'
import AccordionSummary from '@mui/material/AccordionSummary'
import AccordionDetails from '@mui/material/AccordionDetails'
import Typography from '@mui/material/Typography'
import Box from '@mui/material/Box'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import BootLogViewer from './BootLogViewer'

export default function BasicAccordion({ list }) {
  if (!list || !Array.isArray(list)) return null;

  return (
    <div>
      {list.map((acc, index) => {
        return (
          <Accordion key={index}>
            <AccordionSummary
              expandIcon={<ExpandMoreIcon />}
              aria-controls={`panel-${index}-content`}
              id={`panel-${index}-header`}
            >
              <Typography>{acc.title}</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <BootLogViewer>{acc.content}</BootLogViewer>
              </Box>
            </AccordionDetails>
          </Accordion>
        )
      })}
    </div>
  )
}
