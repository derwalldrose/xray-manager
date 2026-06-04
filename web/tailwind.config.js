/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0d1117',
        bg2: '#161b22',
        border: '#30363d',
        text: '#c9d1d9',
        accent: '#58a6ff',
      },
    },
  },
  plugins: [],
}
