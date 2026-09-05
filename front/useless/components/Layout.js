import React from 'react'
import ResponsiveAppBar from './ResponsiveAppbar'


const Layout = ({children}) => {
  return (
    <>
    <ResponsiveAppBar/>
    {children}
    
    </>
  )
}

export default Layout