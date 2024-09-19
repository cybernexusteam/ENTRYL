'use client'

import React, { useState, useEffect } from "react";
import { TextHoverEffect } from "@/components/ui/text-hover-effect";
import Link from "next/link";
import TransitionLayout from '../components/ui/ltod_transition';
export default function Home() {
  const [showButton, setShowButton] = useState(false);
  const [slideUp, setSlideUp] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setSlideUp(true);
      setTimeout(() => setShowButton(true), 300);
    }, 3400);

    return () => clearTimeout(timer);
  }, []);

  return (
       //</TransitionLayout>  <=== TODO figure out how to implement this
    <div className="bg-black min-h-screen flex flex-col items-center justify-center">
      <div className="w-full h-50vh flex flex-col justify-center items-center">
        <div className={`w-full h-[60vh] transition-transform duration-300 ${slideUp ? '-translate-y-8' : ''}`}>
          <TextHoverEffect text='ENTRYL' className="w-full h-full" />
        </div>
        <div className={`mt-8 transition-opacity duration-300 ${showButton ? 'opacity-100' : 'opacity-0'}`}>
          <Link href="/dashboard">
          <button className="mt-2 px-8 py-3 bg-transparent border border-surface1 dark:border-white dark:text-white text-text0 rounded-lg font-bold text-lg transform hover:-translate-y-1 transition duration-400">
          Get Started
            </button>
          </Link>
        </div>
      </div>
    </div>
    //</TransitionLayout>  <=== TODO figure out how to implement this

  );
}