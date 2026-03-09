import './globals.css';

export const metadata = {
  title: 'Cybersecurity Threats & Vulnerabilities Guide',
  description:
    'A comprehensive educational resource providing detailed documentation, detection scripts, and prevention strategies for cybersecurity threats.',
  keywords: 'cybersecurity, threats, vulnerabilities, DDoS, SQL injection, XSS, malware, phishing',
  openGraph: {
    title: 'Cybersecurity Threats & Vulnerabilities Guide',
    description: 'Comprehensive guide to understanding, detecting, and preventing cybersecurity threats.',
    type: 'website',
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
