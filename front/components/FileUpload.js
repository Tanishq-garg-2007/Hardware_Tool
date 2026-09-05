import React, { useRef, useState } from 'react'
import axios from 'axios'
import { Button, TextField } from '@mui/material'
const FileUpload = () => {
  const [file, setFile] = useState()
  const baudRef = useRef()
  const handleUpload = async () => {
    if (!file) {
      alert('Please select a file first')
      return
    }
    const formData = new FormData()
    formData.append('file', file)
    formData.append('baud_rate', baudRef.current.value)
    console.log(formData)

    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await axios.post(
        `${apiBase}/uploadfile/`,
        formData, 
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      )
      console.log(response.data)

      if (response.status >= 200 && response.status < 300) {
        alert('File uploaded successfully')
      } else {
        alert('File upload failed')
      }
    } catch (error) {
      console.error('Error uploading file:', error)
      alert(`Upload error: ${error.response?.data?.detail || error.message}`)
    }
  }
  return (
    <div>
      <TextField
        helperText='Enter the baudrate'
        required
        type='text'
        inputRef={baudRef}
        id='standard-basic'
        label='Baudrate'
        variant='standard'
      />

      <input
        type='file'
        id='file'
        name='file'
        onChange={(e) => setFile(e.target.files[0])}
      ></input>
      <Button sx={{ marginTop: '1em' }} onClick={handleUpload}>
        Submit
      </Button>
    </div>
  )
}

export default FileUpload
