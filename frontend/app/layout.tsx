import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import "antd/dist/reset.css";
import AntdRegistry from "@/components/antd/antd-registry";
import AppThemeProvider from "@/components/theme/app-theme-provider";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "File Manager - Secure File Management",
  description: "Secure file upload and management system with support for configuration files, certificates, and documents.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <AntdRegistry>
          <AppThemeProvider>
            <div className="min-h-screen bg-background">
              {children}
            </div>
          </AppThemeProvider>
        </AntdRegistry>
      </body>
    </html>
  );
}
