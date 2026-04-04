/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,js}'],
  theme: {
    extend: {
      colors: {
        vault: {
          bg: '#2a2a2a',
          surface: '#383838',
          border: '#555555',
          crimson: '#e05555',
          'crimson-light': '#ee6666',
          amber: '#f0c840',
          'amber-light': '#f5d860',
          text: '#ffffff',
          'text-dim': '#e0d8cc',
          'text-muted': '#c8beb0',
          danger: '#f06060',
          success: '#66cc77',
        },
      },
      fontFamily: {
        sans: ['IBM Plex Sans', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        display: ['Playfair Display', 'Georgia', 'serif'],
        mono: ['IBM Plex Mono', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}

