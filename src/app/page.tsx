"use client";

import React, { useState, useEffect } from "react";
import { TextHoverEffect } from "@/components/ui/text-hover-effect";
import { motion } from "framer-motion";
import { AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { useRouter } from "next/navigation";
import {
  SignedIn,
  SignedOut,
  SignInButton,
  UserButton,
} from "@clerk/clerk-react";
export default function Home() {
  const [showButton, setShowButton] = useState(false);
  const [slideUp, setSlideUp] = useState(false);
  const [showContent, setShowContent] = useState(true); // Controls visibility
  const router = useRouter();
  useEffect(() => {
    const timer = setTimeout(() => {
      setSlideUp(true);
      setTimeout(() => setShowButton(true), 300);
    }, 3400);

    return () => clearTimeout(timer);
  }, []);
  const handleButtonClick = () => {
    setShowContent(false);
    setTimeout(() => {
      router.push("./name");
    }, 1000);
  };
  return (
    <div className="bg-black min-h-screen flex flex-col items-center justify-center">
      <AnimatePresence>
        {showContent && (
          <motion.div
            key="home-component"
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 1, type: "spring" }}
            className="w-full h-50vh flex flex-col justify-center items-center"
          >
            <div
              className={`w-full h-[60vh] transition-transform duration-300 ${
                slideUp ? "-translate-y-8" : ""
              }`}
            >
              <TextHoverEffect text="ENTRYL" className="w-full h-full" />
            </div>
            <div
              className={`mt-8 transition-opacity duration-300 ${
                showButton ? "opacity-100" : "opacity-0"
              }`}
            >
              <div className="flex">
                <Button
                  onClick={handleButtonClick}
                  className="mt-2 mx-2 px-8 py-3 h-100 bg-transparent border border-surface1 dark:border-white dark:text-white text-text0 rounded-lg text-lg transform hover:-translate-y-1 transition duration-400"
                >
                  Offline mode
                </Button>
                <SignedOut>
                  <div className="mt-2 mx-2 px-8 py-3 bg-transparent border border-surface1 dark:border-white dark:text-white text-text0 rounded-lg font-bold text-lg transform hover:-translate-y-1 transition duration-400">
                    <SignInButton />
                  </div>
                </SignedOut>
                <SignedIn>
                  <div className="mt-2 mx-2 h-100 px-8 py-3 bg-transparent border border-surface1 dark:border-white dark:text-white text-text0 rounded-lg font-bold text-lg transform hover:-translate-y-1 transition duration-400">
                    <UserButton />
                  </div>
                </SignedIn>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
