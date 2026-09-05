import { Box } from '@mui/system'
import React, { useState } from 'react'
import { Button, Modal, Typography } from '@mui/material'
import Highlighter from 'react-highlight-words'

const style = {
  position: 'absolute',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: 400,
  bgcolor: '#fff',
  border: '2px solid #000',
  boxShadow: 24,
  p: 4,
}


const ModalOverlay = ({handleClose,currentReport,highlightedKeywords}) => {


  let keywords = '['

  for (let index = 0; index < highlightedKeywords.length; index++) {
    const element = highlightedKeywords[index]
    keywords += (element)
    if(index !== highlightedKeywords.length-1) keywords += ' | '
  }

  keywords += ']'
   
  return (
    <Modal
      open={true}
      onClose={handleClose}
      aria-labelledby='modal-modal-title'
      aria-describedby='modal-modal-description'
    >
      <Box sx={style}>
        <Typography id='modal-modal-title' variant='h6' component='h2'>
          {currentReport.title}, Keywords Highlighted: {keywords}
        </Typography>
        <Typography id='modal-modal-description' sx={{ mt: 2 }}>
          <Highlighter
            
            highlightClassName='reportHighlighter'
            searchWords={highlightedKeywords}
            autoEscape={true}
            textToHighlight={currentReport.description}
          />
        </Typography>
      </Box>
    </Modal>
  )
}


export default ModalOverlay