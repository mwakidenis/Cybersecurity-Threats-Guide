'use client';
import { useState } from 'react';
import Link from 'next/link';
import { categories, severityConfig } from '../../../lib/data';

const colorMap = {
  cyan: { accent: '#00e5ff', dim: 'rgba(0,229,255,0.07)', border: 'rgba(0,229,255,0.25)' },
  green: { accent: '#00ff9d', dim: 'rgba(0,255,157,0.07)', border: 'rgba(0,255,157,0.25)' },
  red: { accent: '#ff2d55', dim: 'rgba(255,45,85,0.07)', border: 'rgba(255,45,85,0.25)' },
  yellow: { accent: '#ffd700', dim: 'rgba(255,215,0,0.07)', border: 'rgba(255,215,0,0.25)' },
};

function SeverityBadge({ severity }) {
  const cfg = severityConfig[severity] || severityConfig.INFO;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '5px',
      padding: '2px 8px',
      fontSize: '0.6rem', fontWeight: 700, letterSpacing: '0.1em',
      color: cfg.color,
      background: cfg.bg,
      border: `1px solid ${cfg.color}40`,
    }}>
      <span style={{ width: '5px', height: '5px', borderRadius: '50%', backgroundColor: cfg.color, display: 'inline-block', flexShrink: 0 }} />
      {cfg.label}
    </span>
  );
}

function ThreatPanel({ threat, color }) {
  const [open, setOpen] = useState(false);
  const c = colorMap[color] || colorMap.cyan;

  return (
    <div style={{
      border: '1px solid var(--border)',
      backgroundColor: 'var(--surface)',
      marginBottom: '12px',
      transition: 'all 0.2s ease',
      ...(open ? { borderColor: c.border, boxShadow: `0 0 20px rgba(0,0,0,0.5)` } : {}),
    }}>
      {/* Header */}
      <button
        onClick={() => setOpen(!open)}
        style={{
          width: '100%', textAlign: 'left',
          background: 'none', border: 'none',
          padding: '18px 20px',
          cursor: 'pointer',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '16px',
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flex: 1, minWidth: 0 }}>
          <div style={{
            width: '32px', height: '32px', flexShrink: 0,
            border: `1px solid ${c.accent}30`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            backgroundColor: c.dim,
          }}>
            <span style={{ color: c.accent, fontSize: '0.75rem', fontWeight: 700 }}>
              {threat.id.substring(0, 2).toUpperCase()}
            </span>
          </div>
          <div>
            <div style={{ color: '#e8f4f8', fontSize: '0.85rem', fontWeight: 600 }}>
              {threat.name}
            </div>
            {threat.cvss && threat.cvss !== 'N/A' && (
              <div style={{ color: '#4a7a8a', fontSize: '0.6rem', marginTop: '2px' }}>
                CVSS {threat.cvss}
              </div>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
          <SeverityBadge severity={threat.severity} />
          <span style={{ color: '#4a7a8a', fontSize: '0.75rem', transform: open ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s' }}>
            ▶
          </span>
        </div>
      </button>

      {/* Body */}
      {open && (
        <div style={{ padding: '0 20px 20px', borderTop: '1px solid var(--border)' }}>
          <p style={{ color: '#7aacbc', fontSize: '0.75rem', lineHeight: 1.7, margin: '16px 0' }}>
            {threat.description}
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
            {/* Detection */}
            <div>
              <div style={{
                color: '#00ff9d', fontSize: '0.6rem', letterSpacing: '0.15em',
                textTransform: 'uppercase', marginBottom: '10px',
                display: 'flex', alignItems: 'center', gap: '8px',
              }}>
                <span style={{ width: '12px', height: '1px', background: '#00ff9d', display: 'inline-block' }} />
                Detection Methods
              </div>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                {threat.detection.map((d, i) => (
                  <li key={i} style={{
                    color: '#4a7a8a', fontSize: '0.7rem', lineHeight: 1.6,
                    padding: '4px 0',
                    borderBottom: '1px solid rgba(13,42,53,0.5)',
                    display: 'flex', gap: '8px', alignItems: 'flex-start',
                  }}>
                    <span style={{ color: '#00ff9d', flexShrink: 0, marginTop: '2px' }}>›</span>
                    {d}
                  </li>
                ))}
              </ul>
            </div>

            {/* Prevention */}
            <div>
              <div style={{
                color: c.accent, fontSize: '0.6rem', letterSpacing: '0.15em',
                textTransform: 'uppercase', marginBottom: '10px',
                display: 'flex', alignItems: 'center', gap: '8px',
              }}>
                <span style={{ width: '12px', height: '1px', background: c.accent, display: 'inline-block' }} />
                Prevention Techniques
              </div>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                {threat.prevention.map((p, i) => (
                  <li key={i} style={{
                    color: '#4a7a8a', fontSize: '0.7rem', lineHeight: 1.6,
                    padding: '4px 0',
                    borderBottom: '1px solid rgba(13,42,53,0.5)',
                    display: 'flex', gap: '8px', alignItems: 'flex-start',
                  }}>
                    <span style={{ color: c.accent, flexShrink: 0, marginTop: '2px' }}>›</span>
                    {p}
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Scripts */}
          {threat.scripts && threat.scripts.length > 0 && (
            <div>
              <div style={{ color: '#4a7a8a', fontSize: '0.6rem', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: '8px' }}>
                Related Scripts & Files
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {threat.scripts.map(s => (
                  <span key={s} style={{
                    padding: '3px 10px',
                    background: 'rgba(0,0,0,0.4)',
                    border: '1px solid var(--border)',
                    color: '#4a7a8a',
                    fontSize: '0.65rem',
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function CategoryPage({ params }) {
  const cat = categories.find(c => c.slug === params.slug);

  if (!cat) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ color: '#ff2d55', fontFamily: "'Orbitron', sans-serif", fontSize: '2rem', marginBottom: '16px' }}>404</div>
          <div style={{ color: '#4a7a8a', fontSize: '0.8rem', marginBottom: '24px' }}>Category not found</div>
          <Link href="/" style={{ color: '#00e5ff', fontSize: '0.75rem', textDecoration: 'none' }}>← Return to Index</Link>
        </div>
      </div>
    );
  }

  const c = colorMap[cat.color] || colorMap.cyan;
  const criticalCount = cat.threats.filter(t => t.severity === 'CRITICAL').length;
  const highCount = cat.threats.filter(t => t.severity === 'HIGH').length;

  return (
    <div className="grid-bg" style={{ minHeight: '100vh' }}>
      {/* Top bar */}
      <div style={{
        borderBottom: '1px solid var(--border)',
        backgroundColor: 'rgba(2,6,8,0.95)',
        backdropFilter: 'blur(8px)',
        position: 'sticky', top: 0, zIndex: 100,
        padding: '10px 32px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <Link href="/" style={{
            color: '#4a7a8a', textDecoration: 'none', fontSize: '0.7rem',
            display: 'flex', alignItems: 'center', gap: '6px',
            transition: 'color 0.2s',
          }}
            onMouseEnter={e => e.currentTarget.style.color = '#00e5ff'}
            onMouseLeave={e => e.currentTarget.style.color = '#4a7a8a'}
          >
            ← BACK
          </Link>
          <span style={{ color: 'var(--border)' }}>|</span>
          <span style={{ color: c.accent, fontFamily: "'Orbitron', sans-serif", fontSize: '0.65rem', letterSpacing: '0.2em' }}>
            SEC-{cat.number}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          {criticalCount > 0 && (
            <span style={{ color: '#ff2d55', fontSize: '0.6rem' }}>
              {criticalCount} CRITICAL
            </span>
          )}
          {highCount > 0 && (
            <span style={{ color: '#ff9500', fontSize: '0.6rem' }}>
              {highCount} HIGH
            </span>
          )}
        </div>
      </div>

      <div style={{ maxWidth: '960px', margin: '0 auto', padding: '48px 24px' }}>
        {/* Header */}
        <div style={{ marginBottom: '40px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '16px' }}>
            <span style={{ fontSize: '2.5rem' }}>{cat.icon}</span>
            <div>
              <div style={{ color: '#4a7a8a', fontSize: '0.6rem', letterSpacing: '0.2em', textTransform: 'uppercase', marginBottom: '4px' }}>
                DOMAIN {cat.number} OF 06
              </div>
              <h1 style={{
                fontFamily: "'Bebas Neue', sans-serif",
                fontSize: 'clamp(2rem, 5vw, 3.5rem)',
                color: '#e8f4f8', letterSpacing: '0.05em',
                margin: 0, lineHeight: 1,
              }}>
                {cat.title}
              </h1>
              <div style={{ color: c.accent, fontSize: '0.7rem', letterSpacing: '0.15em', marginTop: '4px' }}>
                {cat.subtitle}
              </div>
            </div>
          </div>
          <p style={{
            color: '#4a7a8a', fontSize: '0.78rem', lineHeight: 1.7,
            maxWidth: '680px',
            borderLeft: `3px solid ${c.accent}`,
            paddingLeft: '16px',
          }}>
            {cat.description}
          </p>
        </div>

        {/* Threat panels */}
        <div style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <span style={{ color: '#4a7a8a', fontSize: '0.65rem', letterSpacing: '0.2em', textTransform: 'uppercase' }}>
            THREAT VECTORS
          </span>
          <div style={{ flex: 1, height: '1px', background: 'var(--border)' }} />
          <span style={{ color: '#4a7a8a', fontSize: '0.65rem' }}>{cat.threats.length} ENTRIES</span>
        </div>

        <div>
          {cat.threats.map(threat => (
            <ThreatPanel key={threat.id} threat={threat} color={cat.color} />
          ))}
        </div>

        {/* Navigation between categories */}
        <div style={{
          display: 'flex', justifyContent: 'space-between', marginTop: '48px',
          paddingTop: '24px', borderTop: '1px solid var(--border)',
          gap: '16px',
        }}>
          {(() => {
            const idx = categories.findIndex(c => c.slug === cat.slug);
            const prev = categories[idx - 1];
            const next = categories[idx + 1];
            return (
              <>
                {prev ? (
                  <Link href={`/category/${prev.slug}/`} style={{
                    color: '#4a7a8a', textDecoration: 'none', fontSize: '0.7rem',
                    display: 'flex', alignItems: 'center', gap: '8px',
                    transition: 'color 0.2s',
                  }}
                    onMouseEnter={e => e.currentTarget.style.color = '#00e5ff'}
                    onMouseLeave={e => e.currentTarget.style.color = '#4a7a8a'}
                  >
                    ← {prev.title}
                  </Link>
                ) : <div />}
                {next && (
                  <Link href={`/category/${next.slug}/`} style={{
                    color: '#4a7a8a', textDecoration: 'none', fontSize: '0.7rem',
                    display: 'flex', alignItems: 'center', gap: '8px',
                    transition: 'color 0.2s',
                  }}
                    onMouseEnter={e => e.currentTarget.style.color = '#00e5ff'}
                    onMouseLeave={e => e.currentTarget.style.color = '#4a7a8a'}
                  >
                    {next.title} →
                  </Link>
                )}
              </>
            );
          })()}
        </div>
      </div>
    </div>
  );
}
