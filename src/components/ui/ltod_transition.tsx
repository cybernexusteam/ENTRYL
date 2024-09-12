"use client";
import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { TextHoverEffect } from '@/components/ui/text-hover-effect';

export default function TransitionLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [isTransitioning, setIsTransitioning] = useState(false);
  const [showTextEffect, setShowTextEffect] = useState(true);

  useEffect(() => {
    const handleRouteChange = (url: string) => {
      setIsTransitioning(true);
      setTimeout(() => {
        router.push(url);
      }, 500); // Adjust this timing to match your transition duration
    };

    window.addEventListener('beforeunload', (event: BeforeUnloadEvent) => {
      if (event.currentTarget instanceof Window) {
        handleRouteChange(event.currentTarget.location.href);
      }
    });

    return () => {
      window.removeEventListener('beforeunload', (event: BeforeUnloadEvent) => {
        if (event.currentTarget instanceof Window) {
          handleRouteChange(event.currentTarget.location.href);
        }
      });
    };
  }, [router]);

  return (
    <div className="relative w-screen h-screen overflow-hidden">
      <AnimatePresence>
        {showTextEffect && (
          <motion.div
            key="text-effect"
            initial={{ x: 0, rotate: 0 }}
            animate={isTransitioning ? { x: '100%', rotate: 90 } : { x: 0, rotate: 0 }}
            exit={{ x: '100%', rotate: 90 }}
            transition={{ duration: 0.5, ease: "easeInOut" }}
            onAnimationComplete={() => {
              if (isTransitioning) {
                setShowTextEffect(false);
                setIsTransitioning(false);
              }
            }}
            className="absolute inset-0 z-10"
          >
            <TextHoverEffect text="ENTRYL" className="w-full h-full" />
          </motion.div>
        )}
      </AnimatePresence>
      <motion.div
        key="page-content"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.3 }}
      >
        {children}
      </motion.div>
    </div>
  );
}