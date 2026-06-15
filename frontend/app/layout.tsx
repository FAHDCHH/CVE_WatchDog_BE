import type { Metadata } from "next";
import { Bebas_Neue, IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import { AppFrame } from "@/components/AppFrame";

// Tactical type system — a tall condensed display face for headers,
// Plex Sans for body, Plex Mono for data/IDs/metrics. All self-hosted by
// next/font (no CDN), which matters in CDN-restricted environments.
const display = Bebas_Neue({
  weight: "400",
  subsets: ["latin"],
  variable: "--font-display",
});
const sans = IBM_Plex_Sans({
  weight: ["400", "500", "600", "700"],
  subsets: ["latin"],
  variable: "--font-sans",
});
const mono = IBM_Plex_Mono({
  weight: ["400", "500", "600"],
  subsets: ["latin"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "CVE WatchDog — Console",
  description: "Threat-intelligence console over the enriched CVE store.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${display.variable} ${sans.variable} ${mono.variable}`}
    >
      <body>
        <AppFrame>{children}</AppFrame>
      </body>
    </html>
  );
}
