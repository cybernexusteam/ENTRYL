import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ClerkProvider } from "@clerk/nextjs";
import { dark, neobrutalism } from "@clerk/themes";
import { AnimatePresence } from "framer-motion";
const inter = Inter({ subsets: ["latin"] });

const clerkFrontendApi = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;

if (!clerkFrontendApi) {
  console.error("NO API");
}

export const metadata: Metadata = {
  title: "ENTRYL",
  description: "Cybersecurity app",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ClerkProvider appearance={{ baseTheme: [dark, neobrutalism] }} publishableKey={clerkFrontendApi || ""}>
      <html lang="en">
        <body className={inter.className}>
          {children}
        </body>
      </html>
      </ClerkProvider>
  );
}


