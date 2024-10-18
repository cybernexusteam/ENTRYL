import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ClerkProvider } from "@clerk/nextjs";
import { dark, neobrutalism } from "@clerk/themes";
const inter = Inter({ subsets: ["latin"] });

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
    
      <html lang="en">
        <body className={inter.className}>
        <ClerkProvider
         appearance={{
          baseTheme: [dark, neobrutalism],
        }}
        >
          {children}
        </ClerkProvider>
        </body>
      </html>
    
  );
}
