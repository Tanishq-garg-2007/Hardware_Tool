import * as React from 'react'


export default function Loader() {
  return (
   <div style = {{position: 'absolute', top:'0', left:'0', width: '100vw', height: '100vh', backgroundColor: 'white', zIndex: '10000'}}>
     <div className="loader">
    <div className="circle"></div>
    <div className="circle"></div>
    <div className="circle"></div>
    <div className="circle"></div>
   </div>
   </div>
   

  )
}
