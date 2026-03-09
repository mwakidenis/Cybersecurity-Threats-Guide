import './globals.css';

export const metadata = {
  title: 'Cybersecurity Threats Guide',
  description: 'Comprehensive guide to understanding, detecting, and preventing cybersecurity threats and vulnerabilities.',
  keywords: 'cybersecurity, threats, vulnerabilities, DDoS, SQL injection, XSS, malware, phishing',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body>{children}</body>
    </html>
  );
}
