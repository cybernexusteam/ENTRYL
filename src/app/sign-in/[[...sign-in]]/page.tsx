'use client'

import * as Clerk from '@clerk/elements/common'
import * as SignIn from '@clerk/elements/sign-in'
import { IconBrandGithub, IconBrandGoogle } from '@tabler/icons-react'
import Image from "next/image";
import LetterLogo from "@/components/ui/LetterLogo.png";
export default function SignInPage() {
  return (
    <div className="grid w-full h-screen flex-grow items-center bg-black px-4 sm:justify-center">
      <SignIn.Root>
        <SignIn.Step
          name="start"
          className="w-full space-y-6 rounded-2xl bg-base px-4 py-10 shadow-md ring-1 ring-black/5 sm:w-96 sm:px-8"
        >
          <header className="text-center">
            <div className='w-full flex justify-center'>
            <Image src={LetterLogo} alt="logo" className='flex justify-center'/>
            </div>
          
            <h1 className="mt-4 text-xl font-medium tracking-tight text-text0">
              Welcome to ENTRYL
            </h1>
          </header>
          <div className="space-y-2">
            <Clerk.Connection
              name="google"
              className="flex w-full items-center justify-center gap-x-3 rounded-md bg-neutral-700 px-3.5 py-1.5 text-sm font-medium text-text0 shadow-[0_1px_0_0_theme(colors.white/5%)_inset,0_0_0_1px_theme(colors.white/2%)_inset] outline-none hover:bg-gradient-to-b hover:from-white/5 hover:to-white/5 focus-visible:outline-[1.5px] focus-visible:outline-offset-2 focus-visible:outline-white active:bg-gradient-to-b active:from-black/20 active:to-black/20 active:text-white/70"
            >
              <IconBrandGoogle className='w-5 m-0'/>
              Login with Google
            </Clerk.Connection>
          </div>
          <div className="space-y-2">
            <Clerk.Connection
              name="github"
              className="flex w-full items-center justify-center gap-x-3 rounded-md bg-neutral-700 px-3.5 py-1.5 text-sm font-medium text-text0 shadow-[0_1px_0_0_theme(colors.white/5%)_inset,0_0_0_1px_theme(colors.white/2%)_inset] outline-none hover:bg-gradient-to-b hover:from-white/5 hover:to-white/5 focus-visible:outline-[1.5px] focus-visible:outline-offset-2 focus-visible:outline-white active:bg-gradient-to-b active:from-black/20 active:to-black/20 active:text-white/70"
            >
              <IconBrandGithub className='w-4 m-0'/>
              Login with Github
            </Clerk.Connection>
          </div>
          <Clerk.GlobalError className="block text-sm text-red-400" />
          <div className="space-y-4">
            <Clerk.Field name="identifier" className="space-y-2">
              <Clerk.Label className="text-sm font-medium text-text0">Username</Clerk.Label>
              <Clerk.Input
                type="text"
                required
                className="w-full rounded-md bg-surface1 px-3.5 py-2 text-sm text-text0 outline-none ring-1 ring-inset ring-surface1 hover:ring-zinc-400 focus:ring-[1.5px] focus:ring-zinc-950 data-[invalid]:ring-red-400"
              />
              <Clerk.FieldError className="block text-sm text-red-400" />
            </Clerk.Field>
            <Clerk.Field name="password" className="space-y-2">
              <Clerk.Label className="text-sm  font-medium text-text0">Password</Clerk.Label>
              <Clerk.Input
                type="password"
                required
                className="w-full rounded-md bg-surface1 px-3.5 py-2 text-sm text-text0 outline-none ring-1 ring-inset ring-surface1 hover:ring-zinc-400 focus:ring-[1.5px] focus:ring-zinc-950 data-[invalid]:ring-red-400"
              />
              <Clerk.FieldError className="block text-sm text-red-400" />
            </Clerk.Field>
          </div>
          <SignIn.Action
            submit
            className="w-full rounded-md bg-surface0 px-3.5 py-1.5 text-center text-sm font-medium text-white shadow outline-none ring-1 ring-inset ring-zinc-950 hover:bg-zinc-800 focus-visible:outline-[1.5px] focus-visible:outline-offset-2 focus-visible:outline-zinc-950 active:text-white/70"
          >
            Sign In
          </SignIn.Action>
          <p className="text-center text-sm text-zinc-500">
            No account?{' '}
            <a
              href="#"
              className="font-medium text-overlay2 decoration-zinc-950/20 underline-offset-4 outline-none hover:text-zinc-700 hover:underline focus-visible:underline"
            >
              Create an account
            </a>
          </p>
          
        </SignIn.Step>
        <SignIn.Step name="verifications">
        <SignIn.Strategy name="email_code">
          <h1>Check your email</h1>
          <p>
            We sent a code to <SignIn.SafeIdentifier />.
          </p>

          <Clerk.Field name="code">
            <Clerk.Label>Email code</Clerk.Label>
            <Clerk.Input />
            <Clerk.FieldError />
          </Clerk.Field>

          <SignIn.Action submit>Continue</SignIn.Action>
        </SignIn.Strategy>
      </SignIn.Step>
      </SignIn.Root>

    </div>
  )
}