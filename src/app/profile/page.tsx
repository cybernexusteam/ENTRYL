"use client";

import { Button } from "@/components/ui/button";
import { Sidebar, SidebarBody, SidebarLink } from "@/components/ui/sidebar";
import { SignOutButton, UserButton, UserProfile } from "@clerk/nextjs";
import {
  IconArrowLeft,
  IconBrandTabler,
  IconSettings,
  IconUserBolt,
} from "@tabler/icons-react";
import { AnimatePresence, motion } from "framer-motion";
import Link from "next/link";
import Image from "next/image";
import { useEffect, useState } from "react";
import LetterLogo from "@/components/ui/LetterLogo.png";
import router from "next/router";

const Profile = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [showContent, setShowContent] = useState(true);
  const [isAnimating, setIsAnimating] = useState(false);
  const handleButtonClick = () => {
    setShowContent(false);
  };
  const [storedUsername, setStoredUsername] = useState<string | null>(null);
  useEffect(() => {
    if (isAnimating) {
      const timeoutId = setTimeout(() => {
      }, 1000);

      return () => clearTimeout(timeoutId);
    }
  }, [isAnimating, router]);
  const links = [
    {
      label: "Dashboard",
      href: "/dashboard",
      icon: (
        <IconBrandTabler className="text-neutral-200 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />
      ),
    },
    {
      label: "Profile",
      href: "../profile",
      icon: (
        <IconUserBolt className="text-neutral-200 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />
      ),
    },
    {
      label: "Settings",
      href: "#",
      icon: (
        <IconSettings className="text-neutral-200 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />
      ),
    },
  ];
  return (
    <AnimatePresence> 
      <div className="bg-black flex items-center w-full h-screen overflow-hidden">
      <Sidebar open={isSidebarOpen} setOpen={setIsSidebarOpen}>
        <SidebarBody className="justify-between gap-10 ">
          <div className="flex flex-col flex-1 overflow-y-auto overflow-x-hidden mt-3">
            <Link
              href="#"
              className="font-normal flex space-x-2 items-center text-sm text-black py-1 relative z-20"
            >
              <Image src={LetterLogo} alt="logo" />
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="font-medium text-text0 dark:text-white whitespace-pre"
              >
                ENTRYL
              </motion.span>
            </Link>
            <div className="mt-8 flex flex-col gap-2">
              {links.map((link, idx) => (
                <Button
                  key={idx}
                  onClick={() => handleButtonClick}
                  className="bg-surface1"
                >
                  <SidebarLink link={link} />
                </Button>
              ))}
            </div>

            <div className="mt-8 flex flex-col gap-2">
              <SignOutButton>
                <Button
                  onClick={() => handleButtonClick}
                  className="bg-surface1"
                >
                  <SidebarLink
                    link={{
                      label: "Logout",
                      href: "/",
                      icon: (
                        <IconArrowLeft className="text-text0 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />
                      ),
                    }}
                  />
                </Button>
              </SignOutButton>
            </div>
          </div>
          <div>
            <SidebarLink
              link={{
                label: storedUsername ? storedUsername : "User",
                href: "#",
                icon: <UserButton />,
              }}
            />
          </div>
        </SidebarBody>
      </Sidebar>

      { showContent && (<motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 3, type: "spring" }}
        exit={{ opacity: 0, y: -20 }}
        className="flex w-full justify-center"
      >
        <UserProfile />
      </motion.div>)}
    </div>
    </AnimatePresence>
    
  );
};

export default Profile;
