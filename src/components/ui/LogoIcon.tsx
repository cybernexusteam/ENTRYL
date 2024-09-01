// src/components/ui/LogoIcon.tsx
import React from 'react';
import Link from 'next/link';

export const LogoIcon = () => {
  return (
    <Link 
      href="#" 
      className="font-normal flex space-x-2 items-center text-sm text-black py-1 relative z-20"
    >
      <div className="h-5 w-6 bg-black dark:bg-white rounded-br-lg rounded-tr-sm rounded-tl-lg rounded-bl-sm flex-shrink-0" />
    </Link>
  );
};
