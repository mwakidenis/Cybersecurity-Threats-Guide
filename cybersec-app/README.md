# Cybersecurity Threats Guide — Web App

A Next.js web application for the [Cybersecurity-Threats-Guide](https://github.com/Bd-Mutant7/Cybersecurity-Threats-Guide) repository, deployable to Vercel.

## Tech Stack
- **Next.js 14** (App Router, Static Export)
- **Tailwind CSS** for utility styling
- **Google Fonts** – JetBrains Mono, Bebas Neue, Orbitron

## Project Structure
```
├── app/
│   ├── layout.jsx         # Root layout with metadata
│   ├── page.jsx           # Home page (category grid + search)
│   ├── globals.css        # Global styles, animations, theme vars
│   └── category/[slug]/
│       └── page.jsx       # Individual category + threat detail page
├── lib/
│   └── data.js            # All threat content (add your own here)
├── next.config.js         # Static export config for Vercel
├── tailwind.config.js
└── vercel.json
```

## Local Development
```bash
npm install
npm run dev
# Visit http://localhost:3000
```

## Deploy to Vercel
1. Push this folder to a GitHub repo
2. Import the repo at vercel.com
3. Vercel auto-detects Next.js — click Deploy

## What to Add / Change / Remove
See the main README in the repo root for full instructions.
