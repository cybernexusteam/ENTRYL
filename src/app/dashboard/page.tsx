'use client'
import React, { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/tauri'
import { BentoGridItem, BentoGrid } from '@/components/ui/bento-grid'
import ENTRYL from '@/components/ui/ENTRYL.png'
import Image from 'next/image'
import { Sidebar, SidebarBody, SidebarLink } from '@/components/ui/sidebar'
import { Logo } from '@/components/ui/Logo'
import {
  IconCpu,
  IconDeviceDesktop,
  IconMeteor,
  IconMap,
  IconArrowLeft,
  IconBrandTabler,
  IconSettings,
  IconUserBolt,
} from "@tabler/icons-react"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent
} from "@/components/ui/chart" // Assuming you saved the chart components in a file named ChartComponents.tsx
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts'

// Define interfaces for our data structures
interface SystemInfo {
  cpu_usage: number;
  total_memory: number;
  used_memory: number;
  total_swap: number;
  used_swap: number;
}

interface Process {
  pid: string;
  name: string;
  cpu_usage: number;
  memory_usage: number;
}

const Dashboard = () => {
  const [open, setOpen] = useState(false)
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null)
  const [processes, setProcesses] = useState<Process[]>([])
  const [cpuData, setCpuData] = useState<{ time: string, usage: number }[]>([])

  useEffect(() => {
    const fetchSystemInfo = async () => {
      try {
        const info = await invoke<string>('get_system_info')
        const parsedInfo = JSON.parse(info)
        setSystemInfo(parsedInfo)
        updateCpuData(parsedInfo.cpu_usage)
      } catch (error) {
        console.error('Error fetching system info:', error)
      }
    }

    const fetchProcesses = async () => {
      try {
        const processesData = await invoke<string>('get_processes')
        setProcesses(JSON.parse(processesData))
      } catch (error) {
        console.error('Error fetching processes:', error)
      }
    }

    fetchSystemInfo()
    fetchProcesses()

    const infoInterval = setInterval(fetchSystemInfo, 1000)
    const processInterval = setInterval(fetchProcesses, 5000)

    return () => {
      clearInterval(infoInterval)
      clearInterval(processInterval)
    }
  }, [])

  // Function to update CPU data with time stamps for chart
  const updateCpuData = (cpuUsage: number) => {
    const currentTime = new Date().toLocaleTimeString()
    setCpuData((prevData) => [
      ...prevData.slice(-10), // Keep only the last 10 entries for performance
      { time: currentTime, usage: cpuUsage },
    ])
  }

  const items = [
    {
      
      title: "CPU Usage",
      description: systemInfo ? `${systemInfo.cpu_usage.toFixed(2)}%` : "Loading...",
      icon: <IconCpu className="h-4 w-4 text-neutral-500" />,
      className: "md:col-span-1",
      
    },
    {
      title: "Memory Usage",
      description: systemInfo 
        ? `${((systemInfo.used_memory / systemInfo.total_memory) * 100).toFixed(2)}%`
        : "Loading...",
      icon: <IconMeteor className="h-4 w-4 text-neutral-500" />,
      className: "md:col-span-1",
    },
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
      description: processes.length > 0 
        ? processes.slice(0, 5).map(p => `${p.name}: ${p.cpu_usage.toFixed(2)}%`).join(', ')
        : "Loading...",
      icon: <IconCpu className="h-4 w-4 text-neutral-500" />,
      className: "md:col-span-2",
    },
  ];

  return (
    <div className='bg-base flex items-center w-full h-screen'>
      <Sidebar open={open} setOpen={setOpen}>
        <SidebarBody className="justify-between gap-10">
          <div className="flex flex-col flex-1 overflow-y-auto overflow-x-hidden">
            <>
              <Logo />
            </>
            <div className="mt-8 flex flex-col gap-2">
              {links.map((link, idx) => (
                <SidebarLink key={idx} link={link} />
              ))}
            </div>
          </div>
          <div>
            <SidebarLink
              link={{
                label: "Test",
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
      <div className='flex max-h-screen w-full'>
        <BentoGrid className='grow max-w-2/3 ml-40 mr-0 md:auto-rows-[30rem]'>
          {items.map((item, i) => (
            <BentoGridItem
              key="CPU USAGE CHART"
              title={item.title}
              description={item.description}
              icon={item.icon}
              className="md:col-span-2"
            />
          ))}
          <ChartContainer config={{ cpu: { label: "CPU Usage" } }}>
            <LineChart data={cpuData}>
              <CartesianGrid strokeDasharray="6 6" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip content={<ChartTooltipContent />} />
              <Legend content={<ChartLegendContent />} />
              <Line type="monotone" dataKey="usage" stroke="#8884d8" />
            </LineChart>
          </ChartContainer>
        </BentoGrid>
        <Image src={ENTRYL} width={900} height={300} alt="logo" className='rotate-90 items-right justify-right h-20 w-50 my-auto flex'/> 
      </div>
    </div>
  )
}

const links = [
  {
    label: "Dashboard",
    href: "#",
    icon: (
      <IconBrandTabler className="text-text0 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />
    ),
  },
  {
    label: "Profile",
    href: "#",
    icon: (
      <IconUserBolt className="text-text0 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />
    ),
  },
  {
    label: "Settings",
    href: "#",
    icon: (
      <IconSettings className="text-text0 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />
    ),
  },
  {
    label: "Logout",
    href: "/",
    icon: (
      <IconArrowLeft className="text-text0 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />
    ),
  },
];

export default Dashboard
