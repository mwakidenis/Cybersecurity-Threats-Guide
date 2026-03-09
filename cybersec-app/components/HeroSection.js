'use client';
import { useEffect, useRef, useState } from 'react';
import { stats } from '../lib/threats-data';

const BOOT_LINES = [
  '> Initializing CTVG v2.0.0...',
  '> Loading threat intelligence database...',
  '> Scanning 6 security categories...',
  '> Indexing 18+ vulnerabilities...',
  '> Loading 45+ detection scripts...',
  '> SYSTEM READY',
];

export default function HeroSection() {
  const [lines, setLines] = useState([]);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let i = 0;
    const interval = setInterval(() => {
      if (i < BOOT_LINES.length) {
        setLines(prev => [...prev, BOOT_LINES[i]]);
        i++;
      } else {
        clearInterval(interval);
        setDone(true);
      }
    }, 280);
    return () => clearInterval(interval);
  }, []);

  return (
    <section style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center',
      padding: '6rem 2rem 4rem',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Background glow */}
      <div style={{
        position: 'absolute',
        top: '20%',
        left: '50%',
        transform: 'translateX(-50%)',
        width: '600px',
        height: '600px',
        background: 'radial-gradient(circle, rgba(0,255,65,0.04) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      <div style={{ maxWidth: '900px', margin: '0 auto', width: '100%', position: 'relative', zIndex: 1 }}>

        {/* Boot terminal */}
        <div style={{
          marginBottom: '2.5rem',
          padding: '1rem 1.25rem',
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.72rem',
          color: 'var(--text-muted)',
          minHeight: '120px',
        }}>
          <div style={{ color: 'var(--green)', opacity: 0.5, marginBottom: '6px', fontSize: '0.65rem' }}>
            ● SYSTEM BOOT — THREAT INTELLIGENCE TERMINAL
          </div>
          {lines.map((line, i) => (
            <div key={i} style={{
              color: line.includes('READY') ? 'var(--green)' : 'var(--text-muted)',
              fontWeight: line.includes('READY') ? 600 : 400,
              animation: 'fadeUp 0.3s ease forwards',
              marginTop: '2px',
            }}>{line}</div>
          ))}
          {!done && (
            <span style={{ color: 'var(--green)', animation: 'blink 1s step-end infinite' }}>█</span>
          )}
        </div>

        {/* Main title */}
        <div style={{ marginBottom: '1.5rem' }}>
          <div style={{
            fontSize: '0.7rem',
            color: 'var(--green)',
            letterSpacing: '0.25em',
            fontWeight: 600,
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}>
            <span style={{
              display: 'inline-block',
              width: '20px',
              height: '1px',
              background: 'var(--green)',
            }}></span>
            EDUCATIONAL RESOURCE
          </div>

          <h1 style={{
            fontFamily: 'var(--font-display)',
            fontSize: 'clamp(2.2rem, 6vw, 4.5rem)',
            fontWeight: 800,
            lineHeight: 1.1,
            color: 'var(--text-bright)',
            letterSpacing: '-0.02em',
          }}>
            Cybersecurity
            <br />
            <span style={{ color: 'var(--green)', textShadow: '0 0 30px rgba(0,255,65,0.3)' }}>
              Threats &
            </span>
            <br />
            Vulnerabilities
          </h1>
        </div>

        <p style={{
          fontSize: '1rem',
          color: 'var(--text-muted)',
          maxWidth: '560px',
          lineHeight: 1.7,
          marginBottom: '3rem',
          fontFamily: 'var(--font-mono)',
        }}>
          Comprehensive documentation, detection scripts, and prevention strategies
          for 18+ cybersecurity threats — built for defenders.
        </p>

        {/* Stats row */}
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '1px',
          marginBottom: '3rem',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          overflow: 'hidden',
        }}>
          {stats.map((s, i) => (
            <div key={i} style={{
              flex: '1 1 120px',
              padding: '1.25rem 1.5rem',
              background: 'var(--surface)',
              borderRight: i < stats.length - 1 ? '1px solid var(--border)' : 'none',
            }}>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: '2rem',
                fontWeight: 800,
                color: 'var(--green)',
                lineHeight: 1,
                marginBottom: '4px',
              }}>{s.value}</div>
              <div style={{
                fontSize: '0.65rem',
                color: 'var(--text-muted)',
                letterSpacing: '0.15em',
                textTransform: 'uppercase',
              }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* CTA Buttons */}
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <a
            href="#categories"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '12px 28px',
              background: 'var(--green)',
              color: '#000',
              fontWeight: 700,
              fontSize: '0.8rem',
              letterSpacing: '0.12em',
              borderRadius: 'var(--radius)',
              transition: 'all 0.2s ease',
              textTransform: 'uppercase',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background = '#00cc33';
              e.currentTarget.style.transform = 'translateY(-1px)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'var(--green)';
              e.currentTarget.style.transform = 'translateY(0)';
            }}
          >
            Explore Threats →
          </a>
          <a
            href="https://github.com/Bd-Mutant7/Cybersecurity-Threats-Guide"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '12px 28px',
              border: '1px solid var(--border2)',
              color: 'var(--text)',
              fontWeight: 600,
              fontSize: '0.8rem',
              letterSpacing: '0.12em',
              borderRadius: 'var(--radius)',
              transition: 'all 0.2s ease',
              textTransform: 'uppercase',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--green)';
              e.currentTarget.style.color = 'var(--green)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--border2)';
              e.currentTarget.style.color = 'var(--text)';
            }}
          >
            View on GitHub
          </a>
        </div>

        {/* Disclaimer banner */}
        <div style={{
          marginTop: '3rem',
          padding: '0.75rem 1rem',
          background: 'rgba(255,45,85,0.07)',
          border: '1px solid rgba(255,45,85,0.25)',
          borderRadius: 'var(--radius)',
          fontSize: '0.7rem',
          color: 'rgba(255,100,120,0.9)',
          letterSpacing: '0.05em',
        }}>
          ⚠ DISCLAIMER — For educational and defensive purposes only. Do not use against systems you don't own or have explicit permission to test.
        </div>
      </div>
    </section>
  );
}
