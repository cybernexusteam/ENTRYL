"use client";

import { Button } from "@/components/ui/button";
import Hero from "@/components/ui/Hero";
import { Sidebar, SidebarBody, SidebarLink } from "@/components/ui/sidebar";
import { SignOutButton, UserButton } from "@clerk/clerk-react";
import {
  IconArrowLeft,
  IconBrandTabler,
  IconSettings,
  IconUserBolt,
} from "@tabler/icons-react";
import axios from "axios";
import { motion } from "framer-motion";
import Link from "next/link";
import { useEffect, useState } from "react";
import Image from "next/image";
import LetterLogo from "@/components/ui/LetterLogo.png";

export default function Page() {
  const [url, setUrl] = useState<string>("");
  const [analyzeResult, setAnalyzeResult] = useState<string | null>(null);
  const handleUrlAnalyze = async () => {
    const res = await axios.get(`/api/virustotal?urlToAnalyze=${url}`);
    setAnalyzeResult(res?.data?.stats);
  };
  const [storedUsername, setStoredUsername] = useState<string | null>(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [showContent, setShowContent] = useState(true);
  const [isAnimating, setIsAnimating] = useState(false);
  const handleButtonClick = () => {
    setShowContent(false);
  };
  const icon: any = {
    "Low Risk": (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="150"
        height="150"
        viewBox="0 0 24 24"
        fill="none"
        stroke="green"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        className="lucide lucide-shield-check"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    ),
    "Moderate Risk": (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="150"
        height="150"
        viewBox="0 0 24 24"
        fill="none"
        stroke="yellow"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        className="lucide lucide-shield-alert"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
        <path d="M12 8v4" />
        <path d="M12 16h.01" />
      </svg>
    ),
    "High Risk": (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="150"
        height="150"
        viewBox="0 0 24 24"
        fill="none"
        stroke="red"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        className="lucide lucide-shield-x"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
        <path d="m14.5 9-5 5" />
        <path d="m9.5 9 5 5" />
      </svg>
    ),
  };
  const links = [
    {
      label: "Dashboard",
      href: "/dashboard",
      icon: <IconBrandTabler className="text-neutral-200 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: "VirusTotal",
      href: "/virustotal",
      icon: <IconUserBolt className="text-neutral-200 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: "profile",
      href: "/profile",
      icon: <IconSettings className="text-neutral-200 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
  ];
  useEffect(() => {
    const username = localStorage.getItem("username");
    setStoredUsername(username);
  }, []);
  return (
    <section className="flex flex-col justify-between bg-zinc-900 min-h-screen">
      <div className="flex">
        <div className="h-screen">
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
                    label: storedUsername || "User",
                    href: "#",
                    icon: <UserButton />,
                  }}
                />
              </div>
            </SidebarBody>
          </Sidebar>
        </div>

        <div className="h-screen flex items-center w-full ">
          <div>
            <Hero />
            <div className="px-4 mx-auto max-w-2xl flex flex-col items-center justify-center">
              <div className="w-full flex flex-col items-center">
                <div className="sm:col-span-2 w-full">
                  <label className="block mb-2 text-md font-medium text-white text-center dark:text-white">
                    Domain or URL to Analyze
                  </label>
                  <input
                    type="text"
                    name="name"
                    id="name"
                    className="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary-600 focus:border-primary-600 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-primary-500 dark:focus:border-primary-500"
                    placeholder="Type domain to check"
                    onChange={(e) => setUrl(e.target.value)}
                  />
                </div>
              </div>
              <button
                type="button"
                className="inline-flex items-center px-5 py-2.5 mt-4 sm:mt-6 text-sm font-medium text-center text-white bg-blue-900 rounded-lg hover:bg-primary-800"
                onClick={handleUrlAnalyze}
              >
                Check URL
              </button>
            </div>
            <div className="flex flex-col justify-center items-center w-full py-5">
              {analyzeResult && icon[analyzeResult]}

              <h3 className="text-md">{analyzeResult}</h3>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}