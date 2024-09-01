'use client'
import React, {useState} from 'react'
import { BentoGridItem, BentoGrid } from '@/components/ui/bento-grid'
import ENTRYL from '@/components/ui/ENTRYL.png'
import LetterLogo from "./LetterLogo.png"
import Image from 'next/image';
import {Sidebar, SidebarBody, SidebarLink} from '@/components/ui/sidebar'
import { motion } from 'framer-motion'
import Link from "next/link";
import { cn } from "@/lib/utils"
import { LogoIcon } from '@/components/ui/LogoIcon'
import { Logo } from '@/components/ui/Logo'
import {
  IconArrowWaveRightUp,
  IconBoxAlignRightFilled,
  IconBoxAlignTopLeft,
  IconClipboardCopy,
  IconFileBroken,
  IconSignature,
  IconTableColumn,
  IconArrowLeft,
  IconBrandTabler,
  IconSettings,
  IconUserBolt,
} from "@tabler/icons-react";


const Dashboard = () => {
  const [open, setOpen] = useState(false);
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
      <BentoGrid className='max-w-2/3 ml-40 mr-0 md:auto-rows-[15rem]  '>
        {items.map((item, i) => (
          <BentoGridItem
            key={i}
            title={item.title}
            description={item.description}
            header={item.header}
            icon={item.icon}
            className={item.className}
          />
        ))}
      </BentoGrid>
      <Image src={ENTRYL} width={900} height={300} alt="logo" className='rotate-90 items-center justify-center h-100 w-50 my-auto flex'/> 
      </div>
    </div>
  )
}
const Skeleton = () => (
  <div className="flex flex-1 w-full h-full min-h-[6rem] rounded-xl bg-gradient-to-br from-surface1 to-surface2"></div>
);
const items = [
  {
    title: "The Dawn of Innovation",
    description: "Explore the birth of groundbreaking ideas and inventions.",
    header: <Skeleton />,
    icon: <IconClipboardCopy className="h-4 w-4 text-neutral-500" />,
    className: "md:row-span-1 md:col-span-2",
  },
  {
    title: "The Digital Revolution",
    description: "Dive into the transformative power of technology.",
    header: <Skeleton />,
    icon: <IconFileBroken className="h-4 w-4 text-neutral-500" />,
    className: "md:row-span-2 md:col-span-4",
  },
 
  {
    title: "The Power of Communication",
    description:
      "Understand the impact of effective communication in our lives.",
    header: <Skeleton />,
    icon: <IconTableColumn className="h-4 w-4 text-neutral-500" />, 
    className: "md:row-span-2 md:col-span-2"
  },
  {
    title: "Knowledge",
    description: "Something is going on here",
    header: <Skeleton />,
    icon: <IconArrowWaveRightUp className="h-4 w-4 text-neutral-500" />,
    
  },
  {
    title: "The Joy of Creation",
    description: "Experience the",
    header: <Skeleton />,
    icon: <IconBoxAlignTopLeft className="h-4 w-4 text-neutral-500" />,
  },
  {
    title: "The Spirit of Adventure",
    description: "Embark on exciting journeys and thrilling discoveries.",
    header: <Skeleton />,
    icon: <IconBoxAlignRightFilled className="h-4 w-4 text-neutral-500" />,
    className: 'md:col-span-2'
  },{
    title: "The Spirit of Adventure",
    description: "Embark on exciting journeys and thrilling discoveries.",
    header: <Skeleton />,
    icon: <IconBoxAlignRightFilled className="h-4 w-4 text-neutral-500" />,
    className: 'md:row-span-2 md:col-span-6'
  },
];
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