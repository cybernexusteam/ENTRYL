'use client'

import React, { useEffect } from 'react';
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { VscArrowRight } from "react-icons/vsc";
import { motion } from "framer-motion";
import Link from 'next/link';
import { AnimatePresence } from 'framer-motion';
import { useRouter } from 'next/navigation';
import { useState } from 'react';


const formSchema = z.object({
  username: z.string().min(2).max(50),
});

const Name = () => {
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      username: '',
    },
  });
  
  const router = useRouter();
  const [isAnimating, setIsAnimating] = useState(false);
  const [showContent, setShowContent] = useState(true);

  const handleSubmit = (values: z.infer<typeof formSchema>) => {
    console.log(values.username);
    localStorage.setItem('username', values.username);

    setIsAnimating(true);
    setShowContent(false);
  };

  useEffect(() => {
    if (isAnimating) {
      const timeoutId = setTimeout(() => {
        router.push('/dashboard');
      }, 1000);

      return () => clearTimeout(timeoutId);
    }
  }, [isAnimating, router]); 

  return (
    
        <motion.div 
          className='bg-black text-text0 w-full h-screen'
        > 
        
          <div className='flex flex-col justify-center items-center h-full'>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(handleSubmit)} className="flex justify-between items-center">
              <AnimatePresence>
              {showContent && (
                  <>
                <motion.div 
                onSubmit={form.handleSubmit(handleSubmit)} 
                exit={{opacity: 0, y: -20}}
                transition={{ duration: 1, type: "spring" }}
                className='flex flex-col justify-center' id='name'
                >
                <motion.div
                    key="form-component"
                    
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 3, type: "spring" }}
                    className='space-x-5 my-2'
                  >
                    What's your name
                  </motion.div>
                  <motion.div
                    key="form-component"
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 1, duration: 2, type: "spring" }}

                    className='flex justify-between items-center'
                  >
                      <FormField
                        control={form.control}
                        name="username"
                        render={({ field }) => (
                          <FormItem>
                            <FormControl>
                              <Input
                                placeholder="Enter your name"
                                {...field}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )} />
                      <Button type="submit" className='ml-10 mt-0' disabled={isAnimating}>
                        <VscArrowRight />
                      </Button>
                    </motion.div>
                </motion.div> 
                </> )}
                </AnimatePresence>       
              </form>
            </Form>
          </div>
        </motion.div>
      
    
    
  );
};

export default Name;