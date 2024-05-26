/** @type {import('next').NextConfig} */
const nextConfig = {};

module.exports = {
  output: "standalone",
  images: {
    domains: ["localhost:80"],
  },
};
