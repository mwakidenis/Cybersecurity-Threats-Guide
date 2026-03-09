/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', 'monospace'],
        display: ['"Bebas Neue"', 'sans-serif'],
      },
      colors: {
        terminal: {
          bg: '#020608',
          surface: '#050d12',
          border: '#0d2a35',
          cyan: '#00e5ff',
          green: '#00ff9d',
          red: '#ff2d55',
          yellow: '#ffd700',
          dim: '#1a3a47',
          text: '#a8c8d8',
          muted: '#4a7a8a',
        },
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        flicker: {
          '0%, 100%': { opacity: '1' },
          '92%': { opacity: '1' },
          '93%': { opacity: '0.6' },
          '94%': { opacity: '1' },
          '96%': { opacity: '0.8' },
          '97%': { opacity: '1' },
        },
        glitch: {
          '0%, 100%': { clipPath: 'inset(0 0 100% 0)', transform: 'translateX(0)' },
          '20%': { clipPath: 'inset(20% 0 60% 0)', transform: 'translateX(-4px)' },
          '40%': { clipPath: 'inset(50% 0 30% 0)', transform: 'translateX(4px)' },
          '60%': { clipPath: 'inset(70% 0 5% 0)', transform: 'translateX(-2px)' },
          '80%': { clipPath: 'inset(10% 0 80% 0)', transform: 'translateX(2px)' },
        },
        pulse_cyan: {
          '0%, 100%': { boxShadow: '0 0 4px #00e5ff40, 0 0 12px #00e5ff20' },
          '50%': { boxShadow: '0 0 8px #00e5ff80, 0 0 24px #00e5ff40' },
        },
        blink: {
          '0%, 49%': { opacity: '1' },
          '50%, 100%': { opacity: '0' },
        },
        fadeIn: {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        scanline: 'scanline 8s linear infinite',
        flicker: 'flicker 6s infinite',
        glitch: 'glitch 0.3s steps(2) 1',
        pulse_cyan: 'pulse_cyan 2s ease-in-out infinite',
        blink: 'blink 1s step-end infinite',
        fadeIn: 'fadeIn 0.4s ease-out forwards',
      },
    },
  },
  plugins: [],
};
