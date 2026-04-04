/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,js}'],
  theme: {
    extend: {
      colors: {
        vault: {
          bg: '#0d0d0d',
          surface: '#1a1a1a',
          border: '#2a2a2a',
          crimson: '#8b1a1a',
          'crimson-light': '#a52a2a',
          amber: '#b8860b',
          'amber-light': '#d4a017',
          text: '#e8dcc8',
          'text-dim': '#8a8070',
          'text-muted': '#5a5248',
          danger: '#cc3333',
          success: '#2d6b3f',
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

