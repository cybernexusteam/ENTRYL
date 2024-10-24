"use client";

import React, { useState, useEffect } from "react";
import { BentoGrid, BentoGridItem } from "@/components/ui/bento-grid";
import { Button } from "@/components/ui/button";
import {
  ChartContainer,
  ChartLegendContent,
  ChartTooltipContent,
} from "@/components/ui/chart";
import LetterLogo from "@/components/ui/LetterLogo.png";
import { Sidebar, SidebarBody, SidebarLink } from "@/components/ui/sidebar";
import {
  IconArrowLeft,
  IconBrandTabler,
  IconCpu,
  IconDeviceDesktop,
  IconSettings,
  IconUserBolt,
} from "@tabler/icons-react";
import { invoke } from "@tauri-apps/api/tauri";
import { AnimatePresence, motion } from "framer-motion";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { open } from "@tauri-apps/api/dialog";
import {
  AlertDialog,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogFooter,
} from "@/components/ui/alert";
import { Area, Legend, Line, LineChart, ResponsiveContainer, Tooltip, YAxis } from "recharts";
import { Process } from "tauri-plugin-system-info-api";
import { PlaceholdersAndVanishInput } from "@/components/ui/placeholders-and-vanish-input";
import { TextGenerateEffect } from "@/components/ui/text-generate-effect";


type SystemInfo = {
  total_memory: number;
  used_memory: number;
  cpu_usage: number;
};

type PredictionResult = {
  sha256: string;
  prediction: string;
};

const Dashboard = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [cpuData, setCpuData] = useState<{ time: string; usage: number }[]>([]);
  const [memoryData, setMemoryData] = useState<{ time: string; usage: number }[]>([]);
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [storedUsername, setStoredUsername] = useState<string | null>(null);
  const [showContent, setShowContent] = useState(true);
  const [isAlertOpen, setIsAlertOpen] = useState(false);
  const [alertTitle, setAlertTitle] = useState("");
  const [alertMessage, setAlertMessage] = useState("");
  const [assistantResponse, setAssistantResponse] = useState('Welcome! How can I help you today?');
  const [isProcessing, setIsProcessing] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const username = localStorage.getItem("username");
    setStoredUsername(username);
    
    const fetchSystemInfo = async () => {
      try {
        const info = await invoke<string>("get_system_info");
        const parsedInfo = JSON.parse(info);
        setSystemInfo(parsedInfo);
        updateCpuData(parsedInfo.cpu_usage);
        updateMemoryData(parsedInfo.used_memory, parsedInfo.total_memory);
      } catch (error) {
        console.error("Error fetching system info:", error);
      }
    };

    const fetchProcesses = async () => {
      try {
        const processesData = await invoke<string>("get_processes");
        setProcesses(JSON.parse(processesData));
      } catch (error) {
        console.error("Error fetching processes:", error);
      }
    };

    fetchSystemInfo();
    fetchProcesses();

    const infoInterval = setInterval(fetchSystemInfo, 65);
    const processInterval = setInterval(fetchProcesses, 1000);

    return () => {
      clearInterval(infoInterval);
      clearInterval(processInterval);
    };
  }, []);

  const updateCpuData = (cpuUsage: number) => {
    const currentTime = new Date().toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      fractionalSecondDigits: 3,
    });
    setCpuData((prevData) => [...prevData.slice(-40), { time: currentTime, usage: cpuUsage }]);
  };

  const updateMemoryData = (usedMemory: number, totalMemory: number) => {
    const currentTime = new Date().toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      fractionalSecondDigits: 3,
    });
    const memoryUsage = (usedMemory / totalMemory) * 100;
    setMemoryData((prevData) => [...prevData.slice(-40), { time: currentTime, usage: memoryUsage }]);
  };

  const handleScanClick = async () => {
    const selectedDirectory = await open({
      directory: true,
      multiple: false,
    });


    if (selectedDirectory) {
      setScanStatus("Scanning... Please wait.");
      try {
        // Invoke the Rust command and explicitly type the response
        const results = await invoke<PredictionResult[]>("scan_and_get_results");
        
        // Check for malware, case-insensitive comparison
        const hasMalware = results.some(
          result => result.prediction.toLowerCase() === "malware"
        );
        
        // Set alert title with emoji
        setAlertTitle(hasMalware ? "⚠️ WARNING" : "✅ GOOD");
        
        // Create detailed alert message
        if (hasMalware) {
          const malwareFiles = results
            .filter(result => result.prediction.toLowerCase() === "malware")
            .map(result => `SHA256: ${result.sha256}`)
            .join("\n");
            
          setAlertMessage(
            `Malicious files detected:\n\n${malwareFiles}\n\nPlease review these files carefully and consider removing them.`
          );
        } else {
          setAlertMessage("No malicious files found. Your system is clean!");
        }
        
        setIsAlertOpen(true);
        setScanStatus("Scan completed.");
      } catch (error) {
        console.error("Error during scan:", error);
        setScanStatus(`Error: ${error}`);
      }
    } else {
      setScanStatus("No directory selected.");
    }
  };

  const items = [
    {
      title: "Total Memory",
      description: systemInfo
        ? `${(systemInfo.total_memory / 1024 / 1024 / 1024).toFixed(2)} GB`
        : "Loading...",
      icon: <IconDeviceDesktop className="h-4 w-4 text-neutral-500" />,
      className: "md:col-span-1",
    },
    {
      title: "Top Processes",
      description: (
        <ul className="list-disc list-inside">
          {processes.slice(0, 5).map((p) => (
            <li key={p.pid}>
              {p.name}: {p.cpu_usage.toFixed(2)}%
            </li>
          ))}
        </ul>
      ),
      icon: <IconCpu className="h-4 w-4 text-neutral-500" />,
      className: "md:col-span-1",
    },
  ];

  const links = [
    {
      label: "Dashboard",
      href: "#",
      icon: <IconBrandTabler className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: "VirusTotal",
      href: "/virustotal",
      icon: <IconUserBolt className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: "Settings",
      href: "#",
      icon: <IconSettings className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: "Logout",
      href: "/",
      icon: <IconArrowLeft className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
  ];

  return (
    <AnimatePresence>
      {showContent && (
        <motion.div className="bg-black flex items-center w-full h-screen overflow-hidden">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 1, delay: 1 }}
            className="h-screen"
          >
            <Sidebar open={isSidebarOpen} setOpen={setIsSidebarOpen}>
              <SidebarBody className="justify-between gap-10">
                <div className="flex flex-col flex-1 overflow-y-auto overflow-x-hidden mt-3">
                  <Link href="#" className="font-normal flex space-x-2 items-center text-sm text-black py-1 relative z-20">
                    <Image src={LetterLogo} alt="logo" />
                    <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="font-medium text-text0 dark:text-white whitespace-pre">
                      ENTRYL
                    </motion.span>
                  </Link>
                  <div className="mt-8 flex flex-col gap-2">
                    {links.map((link, idx) => (
                      <Button key={idx} onClick={() => link.href === "/" && router.push("/")} className="bg-surface1">
                        <SidebarLink link={link} />
                      </Button>
                    ))}
                  </div>
                </div>
                <div>
                  <SidebarLink
                    link={{
                      label: storedUsername || "User",
                      href: "#",
                      icon: (
                        <Image
                          src=""
                          className="h-7 w-7 flex-shrink-0 rounded-full border-black border-2"
                          width={50}
                          height={50}
                          alt="Avatar"
                        />
                      ),
                    }}
                  />
                </div>
              </SidebarBody>
            </Sidebar>
          </motion.div>

          <div className="flex flex-col h-[70vh] w-full mr-10">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 3, type: "spring" }}
              exit={{ opacity: 0, y: -20 }}
              className="ml-14 my-auto"
            >
              <span className="text-text0 dark:text-white text-8xl relative top-[-90px]">
                Hi, {storedUsername ? storedUsername + "   👋" : "User"}.
              </span>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7, duration: 3, type: "spring" }}
              exit={{ opacity: 0, y: -20 }}
              className="w-full flex justify-between mx-10 max-h-1/2"
            >
              <div className="w-full flex flex-col items-center justify-center">
                <div className="flex w-full gap-6">
                  <div className="flex flex-col gap-6 w-[500px]">
                    <BentoGrid className="w-[500px]">
                      {items.map((item, i) => (
                        <BentoGridItem
                          key={i}
                          title={item.title}
                          description={item.description}
                          icon={item.icon}
                          className={item.className}
                        />
                      ))}
                    </BentoGrid>
                    <div className="w-full h-full p-5 bg-opacity-20 bg-surface0 border-2 border-opacity-20 border-text0 rounded-xl">
                      <motion.h1 className="text-text0 font-extrabold text-4xl">
                        ANTIMALWARE CLEANING
                      </motion.h1>
                      <Button onClick={handleScanClick} className="mt-4">
                        Start Scan
                      </Button>
                      {scanStatus && <p className="mt-2 text-text0">{scanStatus}</p>}
                    </div>
                  </div>

                  <div className="max-w-1/2 grid md:grid-cols-1 h-[70vh] gap-6">
                    <div className="p-5 bg-opacity-20 bg-surface0 border-2 border-opacity-20 border-text0 rounded-xl">
                      <motion.h1 className="text-text0 font-bold my-3">
                        CPU Usage:
                        <span className="text-text0 dark:text-white font-normal">
                          {systemInfo ? ` ${systemInfo.cpu_usage.toFixed(2)}%` : " Loading..."}
                        </span>
                      </motion.h1>
                      <ChartContainer config={{ cpu: { label: "CPU Usage" } }} className="h-[25vh] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={cpuData} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
                            <YAxis domain={[0, 100]} />
                            <Tooltip content={<ChartTooltipContent />} />
                            <Legend content={<ChartLegendContent />} />
                            <Line type="monotone" dataKey="usage" stroke="#8884d8" dot={false} />
                            <Area
                              name="CPU Usage"
                              type="monotone"
                              dataKey="usage"
                              stroke="#8884d8"
                              fillOpacity={1}
                              fill="url(#CPU Usage)"
                            />
                          </LineChart>
                        </ResponsiveContainer>
                      </ChartContainer>
                    </div>
                    
                    <div className="w-full h-full p-5 bg-opacity-20 bg-surface0 border-2 border-opacity-20 border-text0 rounded-xl overflow-hidden">
  <motion.h1 className="text-text0 font-bold my-3">
    Memory Usage:
    <span className="text-text0 dark:text-white font-normal">
      {systemInfo
        ? ` ${((systemInfo.used_memory / systemInfo.total_memory) * 100).toFixed(2)}%`
        : " Loading..."}
    </span>
  </motion.h1>
  <ChartContainer config={{ memory: { label: "Memory Usage" } }} className="h-[25vh] w-full">
    <ResponsiveContainer width="99%" height="100%">
      <LineChart data={memoryData} margin={{ top: 5, right: 5, left: 5, bottom: 5 }}>
        <YAxis domain={[0, 100]} />
        <Tooltip content={<ChartTooltipContent />} />
        <Legend content={<ChartLegendContent />} />
        <Line type="monotone" dataKey="usage" stroke="#82ca9d" dot={false} />
      </LineChart>
    </ResponsiveContainer>
  </ChartContainer>
</div>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
          <div className="w-full h-84 p-5 bg-opacity-20 bg-surface0 border-2 border-opacity-20 border-text0 rounded-xl">
  <motion.h1 
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    className="text-text0 font-extrabold text-4xl mb-4"
  >
    AI ASSISTANT
  </motion.h1>
  <div className="flex flex-col gap-4">
    <PlaceholdersAndVanishInput 
      placeholders={[
        "Ask me about system security...",
        "Need help with analysis?",
        "Type your question here..."
      ]}
      onChange={(e) => {
        // Handle change event if needed
      }}
      onSubmit={async (e) => {
        e.preventDefault();
        const inputElement = e.currentTarget.elements[0] as HTMLInputElement;
        const userInput = inputElement.value.trim();
        
        if (!userInput) return;
        
        setIsProcessing(true);
        try {
          const res = await fetch('/api/fetchChatResponse', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ userInput }),
          });
          
          if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
          }
          
          const data = await res.json();
          setAssistantResponse(data.response || 'I apologize, but I received an empty response.');
          inputElement.value = ''; // Clear input after successful submission
        } catch (error) {
          console.error('Error:', error);
          setAssistantResponse('Sorry, I encountered an error processing your request. Please try again.');
        } finally {
          setIsProcessing(false);
        }
      }}
    />
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="mt-4 p-4 rounded-lg bg-black bg-opacity-50 min-h-[200px] text-text0"
    >
      {isProcessing ? (
        <div className="flex items-center justify-center h-full">
          <div className="text-text0">Processing your request...</div>
        </div>
      ) : (
        <TextGenerateEffect words={assistantResponse} />
      )}
    </motion.div>
  </div>
</div>

          <AlertDialog open={isAlertOpen} onOpenChange={setIsAlertOpen}>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{alertTitle}</AlertDialogTitle>
                <AlertDialogDescription className="whitespace-pre-line">
                  {alertMessage}
                  </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction>Continue</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </motion.div>
      )}
    </AnimatePresence>
    
  );
};

<div className="flex justify-center items-center w-full py-5 text-white">
Made with ❤️
</div>
export default Dashboard;