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

const formSchema = z.object({
  username: z.string().min(2).max(50),
});

const Name = () => {
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      username: '', // This will be populated with the value from localStorage later
    },
  });

  // Populate the form with the username from localStorage when the component mounts
  useEffect(() => {
    const storedUsername = localStorage.getItem('username');
    if (storedUsername) {
      form.setValue('username', storedUsername); // Set the form value from localStorage
    }
  }, [form]);

  const handleSubmit = (values: z.infer<typeof formSchema>) => {
    console.log(values.username);
    // Store the username in local storage
    localStorage.setItem('username', values.username);
  };

  return (
    <div className='bg-black text-text0 w-full h-screen'> 
      <div className='flex flex-col justify-center items-center h-full'>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(handleSubmit)} className="flex justify-between items-center">
            <div className='flex flex-col justify-center' id='name'>
              <motion.div 
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 3, type: "spring" }}
                exit={{ opacity: 0, y: -20 }}
                className='space-x-5 my-2'
              >
                What's your name
              </motion.div>
              <motion.div 
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 1, duration: 3, type: "spring" }}
                exit={{ opacity: 0, y: -20 }}
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
                          {...field} // This is controlled by react-hook-form
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit" className='ml-10 mt-0'>
                  <Link href={"/dashboard"}>
                    <VscArrowRight />
                  </Link>
                </Button>         
              </motion.div>
            </div>        
          </form>
        </Form>
      </div>
    </div>
  );
};

export default Name;