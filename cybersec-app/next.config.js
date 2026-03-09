/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'export',       // ← keep for static/GitHub Pages hosting; remove if you add API routes
  trailingSlash: true,
  images: { unoptimized: true },
  env: {
    BUILD_DATE: new Date().toISOString(), // baked in at `next build` time
  },
};

module.exports = nextConfig;
