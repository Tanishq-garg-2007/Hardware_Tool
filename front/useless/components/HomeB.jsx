import { Button, Modal, Typography } from '@mui/material';
import { Box } from '@mui/system';
import { useRouter } from 'next/router';
import React, { useState } from 'react';




const HomeB = (props) => {
  const redirect= ()=> {props.link};
  const style = {
    position: 'absolute' ,
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    width: 400,
    bgcolor: '#fff',
    border: '2px solid #000',
    boxShadow: 24,
    p: 4,
  };

  const [Name,setname]=useState(false);
  const handleOpen= ()=>setname(true);
  const handleClose=()=>setname(false);


  const router = useRouter()



return (
   
    <div className='my-style' style={{textAlign:'center', width: '18rem', margin:'1rem'}}>
      <Button variant="contained" onClick={handleOpen} style={{width:'inherit', height: 'rem'}}>{props.nam}</Button>
      {Name  && <Modal open={Name}
  onClose={handleClose}
  aria-labelledby="modal-modal-title"
  aria-describedby="modal-modal-description"
>
  <Box sx={style}>
    <Typography id="modal-modal-title" variant="h6" component="h2">
      {props.distit}
    </Typography>
    <Typography id="modal-modal-description" sx={{ mt: 2 }}>
      {props.dis}
    </Typography>
    <Button variant="contained" onClick={() => router.push(props.lin)}>{props.nam}</Button>
  </Box>
  
</Modal>}
  

    </div>
  )
}

export default HomeB
