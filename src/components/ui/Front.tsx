import React from 'react'
import Image from 'next/image'
import Link from 'next/link'
import Logo from './Logo.png'
const page = () => {
  return (
    <div className="w-full h-screen flex flex-col justify-center items-center bg-black">
        <Image src={Logo} alt="logo" className=""/>
        
    </div>
  )
}

export default page