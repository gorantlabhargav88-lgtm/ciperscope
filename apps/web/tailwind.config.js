/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        security: {
          critical: '#e11d48', // rose-600
          high: '#f97316', // orange-500
          medium: '#f59e0b', // amber-500
          low: '#3b82f6', // blue-500
          info: '#64748b', // slate-500
          verified: '#10b981', // emerald-500
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
