/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: { 900: "#050b1a", 800: "#0a1428", 700: "#0f1d3a", 600: "#16294f" },
        cyan: { 400: "#22d3ee", 500: "#06b6d4" },
        brand: { 500: "#3b82f6" },
      },
      boxShadow: { card: "0 10px 30px -12px rgba(2, 12, 27, 0.7)" },
    },
  },
  plugins: [],
};

