import React from 'react'
import Image from 'next/image'
import ENTRYL from './ENTRYL.png'
import Link from 'next/link'
const page = () => {
  return (
    <div className="w-full h-screen flex flex-col justify-center items-center bg-black">
      
        <Image src={ENTRYL} alt="logo" className=""/>

        <Link href={"/dashboard"}> 
          <button className="shadow-[0_0_0_3px_#000000_inset] px-6 py-2 bg-transparent border border-surface1 dark:border-white dark:text-white text-text0 rounded-lg font-bold transform hover:-translate-y-1 transition duration-400 mt-10">
            Get Started 
          </button>
        </Link>
    </div>
  )
}

export default page