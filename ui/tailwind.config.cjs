/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#07111f",
        mist: "#d4ecff",
        pulse: "#99f6e4",
        ember: "#ff8b6a",
        amber: "#f8d46b",
        signal: "#6eff9b"
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(212, 236, 255, 0.08), 0 20px 60px rgba(2, 6, 23, 0.35)"
      },
      backgroundImage: {
        "control-grid":
          "radial-gradient(circle at top, rgba(153, 246, 228, 0.22), transparent 38%), linear-gradient(135deg, rgba(255, 255, 255, 0.06), transparent), linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px)"
      },
      fontFamily: {
        display: ["Space Grotesk", "Segoe UI", "sans-serif"],
        body: ["Sora", "Segoe UI", "sans-serif"]
      }
    }
  },
  plugins: []
};
