import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        graphite: {
          950: "#0E1116",
          900: "#14171C",
          850: "#181C23",
          800: "#1C2128",
          700: "#252B33",
          600: "#333B46",
          500: "#4A5461",
        },
        signal: {
          allow: "#2FB170",
          review: "#F5A623",
          block: "#E5484D",
          analyze: "#6E7BFF",
        },
        mist: {
          100: "#F3F5F7",
          300: "#C7CDD6",
          500: "#8892A0",
        },
      },
      fontFamily: {
        display: ["var(--font-display)"],
        body: ["var(--font-body)"],
        mono: ["var(--font-mono)"],
      },
      boxShadow: {
        panel: "0 1px 0 rgba(255,255,255,0.04) inset, 0 12px 32px -12px rgba(0,0,0,0.6)",
      },
      keyframes: {
        pulseDot: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.35" },
        },
        scan: {
          "0%": { backgroundPosition: "0% 0%" },
          "100%": { backgroundPosition: "0% -200%" },
        },
      },
      animation: {
        pulseDot: "pulseDot 1.4s ease-in-out infinite",
        scan: "scan 6s linear infinite",
      },
    },
  },
  plugins: [],
};
export default config;
