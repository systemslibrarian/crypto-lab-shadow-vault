/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,js}'],
  theme: {
    extend: {
      colors: {
        vault: {
          bg: '#1a1a1a',
          surface: '#262626',
          border: '#3a3a3a',
          crimson: '#a52a2a',
          'crimson-light': '#c04040',
          amber: '#d4a017',
          'amber-light': '#e6b830',
          text: '#f0e6d6',
          'text-dim': '#b0a090',
          'text-muted': '#8a7e72',
          danger: '#e04444',
          success: '#3d8b50',
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

