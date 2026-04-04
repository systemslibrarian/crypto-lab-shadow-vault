/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,js}'],
  theme: {
    extend: {
      colors: {
        vault: {
          bg: '#2a2a2a',
          surface: '#353535',
          border: '#4a4a4a',
          crimson: '#cc4444',
          'crimson-light': '#dd5555',
          amber: '#e8b830',
          'amber-light': '#f0cc50',
          text: '#f5f0e8',
          'text-dim': '#ccc0b0',
          'text-muted': '#a89888',
          danger: '#f05555',
          success: '#55aa66',
        },
      },
      fontFamily: {
        display: ['Playfair Display', 'Georgia', 'serif'],
        mono: ['IBM Plex Mono', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}

