'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { categories, stats } from '../lib/data';

const colorMap = {
  cyan: { accent: '#00e5ff', dim: 'rgba(0,229,255,0.08)', border: 'rgba(0,229,255,0.25)' },
  green: { accent: '#00ff9d', dim: 'rgba(0,255,157,0.08)', border: 'rgba(0,255,157,0.25)' },
  red: { accent: '#ff2d55', dim: 'rgba(255,45,85,0.08)', border: 'rgba(255,45,85,0.25)' },
  yellow: { accent: '#ffd700', dim: 'rgba(255,215,0,0.08)', border: 'rgba(255,215,0,0.25)' },
};

function StatBlock({ value, label, delay }) {
  return (
    <div className="fade-in" style={{ animationDelay: `${delay}s`, opacity: 0 }}>
      <div style={{ color: '#00e5ff', fontSize: '1.8rem', fontFamily: "'Orbitron', sans-serif", fontWeight: 900, lineHeight: 1 }}>
        {value}
      </div>
      <div style={{ color: '#4a7a8a', fontSize: '0.65rem', letterSpacing: '0.12em', marginTop: '4px', textTransform: 'uppercase' }}>
        {label}
      </div>
    </div>
  );
}

function CategoryCard({ cat, index }) {
  const [hovered, setHovered] = useState(false);
  const color = colorMap[cat.color] || colorMap.cyan;

  return (
    <Link
      href={`/category/${cat.slug}/`}
      className="fade-in threat-card"
      style={{
        display: 'block',
        borderRadius: '2px',
        padding: '24px',
        textDecoration: 'none',
        position: 'relative',
        overflow: 'hidden',
        animationDelay: `${0.1 + index * 0.08}s`,
        opacity: 0,
        borderColor: hovered ? color.border : 'var(--border)',
        backgroundColor: hovered ? color.dim : 'var(--surface)',
        transition: 'all 0.25s ease',
        boxShadow: hovered ? `0 0 0 1px ${color.border}, 0 12px 40px rgba(0,0,0,0.6)` : 'none',
        transform: hovered ? 'translateY(-3px)' : 'none',
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      {/* Corner accent */}
      <div style={{
        position: 'absolute', top: 0, left: 0,
        width: '40px', height: '40px',
        borderTop: `2px solid ${color.accent}`,
        borderLeft: `2px solid ${color.accent}`,
        opacity: hovered ? 1 : 0.4,
        transition: 'opacity 0.25s',
      }} />
      <div style={{
        position: 'absolute', bottom: 0, right: 0,
        width: '24px', height: '24px',
        borderBottom: `1px solid ${color.accent}`,
        borderRight: `1px solid ${color.accent}`,
        opacity: hovered ? 0.7 : 0.2,
        transition: 'opacity 0.25s',
      }} />

      {/* Number */}
      <div style={{
        color: color.accent,
        fontFamily: "'Orbitron', sans-serif",
        fontSize: '0.6rem',
        letterSpacing: '0.2em',
        marginBottom: '12px',
        opacity: 0.6,
      }}>
        SEC-{cat.number}
      </div>

      {/* Icon + Title */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', marginBottom: '10px' }}>
        <span style={{ fontSize: '1.6rem', lineHeight: 1 }}>{cat.icon}</span>
        <div>
          <div style={{
            color: '#e8f4f8',
            fontSize: '1rem',
            fontWeight: 600,
            letterSpacing: '0.05em',
            lineHeight: 1.2,
          }}>
            {cat.title}
          </div>
          <div style={{
            color: color.accent,
            fontSize: '0.65rem',
            letterSpacing: '0.15em',
            textTransform: 'uppercase',
            marginTop: '2px',
            opacity: 0.8,
          }}>
            {cat.subtitle}
          </div>
        </div>
      </div>

      {/* Description */}
      <p style={{
        color: '#4a7a8a',
        fontSize: '0.72rem',
        lineHeight: 1.6,
        margin: '0 0 16px',
      }}>
        {cat.description.substring(0, 120)}...
      </p>

      {/* Threat count */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderTop: '1px solid var(--border)',
        paddingTop: '12px',
      }}>
        <div style={{ color: '#4a7a8a', fontSize: '0.65rem' }}>
          {cat.threats.length} THREAT VECTORS
        </div>
        <div style={{
          color: color.accent,
          fontSize: '0.65rem',
          letterSpacing: '0.1em',
          opacity: hovered ? 1 : 0,
          transform: hovered ? 'translateX(0)' : 'translateX(-4px)',
          transition: 'all 0.2s ease',
        }}>
          ACCESS →
        </div>
      </div>
    </Link>
  );
}

export default function HomePage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [time, setTime] = useState('');
  const [filtered, setFiltered] = useState(categories);

  useEffect(() => {
    const tick = () => setTime(new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!searchQuery.trim()) { setFiltered(categories); return; }
    const q = searchQuery.toLowerCase();
    setFiltered(categories.filter(c =>
      c.title.toLowerCase().includes(q) ||
      c.subtitle.toLowerCase().includes(q) ||
      c.threats.some(t => t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q))
    ));
  }, [searchQuery]);

  return (
    <div className="grid-bg" style={{ minHeight: '100vh', padding: '0' }}>
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
          <div style={{
            width: '8px', height: '8px', borderRadius: '50%',
            backgroundColor: '#00ff9d',
            boxShadow: '0 0 8px #00ff9d',
            animation: 'pulse_cyan 2s infinite',
          }} />
          <span style={{ color: '#00e5ff', fontFamily: "'Orbitron', sans-serif", fontSize: '0.7rem', letterSpacing: '0.2em' }}>
            CYBERSEC-GUIDE v2.1
          </span>
          <span style={{ color: 'var(--border)', fontSize: '0.7rem' }}>|</span>
          <span style={{ color: '#4a7a8a', fontSize: '0.65rem' }}>EDUCATIONAL RESOURCE</span>
        </div>
        <div style={{ color: '#4a7a8a', fontSize: '0.6rem', fontFamily: "'JetBrains Mono', monospace" }}>
          {time}
        </div>
      </div>

      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '48px 24px' }}>
        {/* Hero */}
        <div style={{ marginBottom: '56px' }}>
          <div className="fade-in" style={{ opacity: 0, animationDelay: '0s' }}>
            <div style={{
              color: '#4a7a8a', fontSize: '0.65rem', letterSpacing: '0.25em',
              textTransform: 'uppercase', marginBottom: '12px',
            }}>
              ▸ CLASSIFIED KNOWLEDGE BASE ▸ DEFENSIVE OPERATIONS
            </div>
          </div>

          <h1 className="fade-in" style={{
            fontFamily: "'Bebas Neue', sans-serif",
            fontSize: 'clamp(3rem, 8vw, 6.5rem)',
            lineHeight: 0.9,
            letterSpacing: '0.04em',
            margin: '0 0 16px',
            opacity: 0,
            animationDelay: '0.05s',
          }}>
            <span style={{ display: 'block', color: '#e8f4f8' }}>CYBERSECURITY</span>
            <span style={{ display: 'block', color: '#00e5ff', textShadow: '0 0 40px rgba(0,229,255,0.4)' }}>THREATS</span>
            <span style={{ display: 'block', color: '#4a7a8a' }}>& VULNERABILITIES</span>
          </h1>

          <p className="fade-in" style={{
            color: '#4a7a8a', fontSize: '0.8rem', lineHeight: 1.7,
            maxWidth: '560px', opacity: 0, animationDelay: '0.1s',
            marginBottom: '32px',
          }}>
            A comprehensive educational resource providing detailed documentation, detection scripts, and prevention strategies for {stats.totalTopics} threat categories across {stats.totalSections} domains.
          </p>

          {/* Stats row */}
          <div className="fade-in" style={{
            display: 'flex', gap: '40px', flexWrap: 'wrap',
            padding: '20px 24px',
            border: '1px solid var(--border)',
            borderLeft: '3px solid var(--cyan)',
            backgroundColor: 'var(--surface)',
            marginBottom: '32px',
            opacity: 0, animationDelay: '0.15s',
          }}>
            <StatBlock value={stats.totalSections} label="Sections" delay={0.2} />
            <StatBlock value={stats.totalTopics} label="Topics" delay={0.25} />
            <StatBlock value={stats.pythonScripts} label="Python Scripts" delay={0.3} />
            <StatBlock value={stats.shellScripts} label="Shell Scripts" delay={0.35} />
            <StatBlock value={stats.docFiles} label="Doc Files" delay={0.4} />
          </div>

          {/* Disclaimer */}
          <div className="fade-in" style={{
            display: 'flex', gap: '12px', alignItems: 'flex-start',
            padding: '12px 16px',
            backgroundColor: 'rgba(255,45,85,0.06)',
            border: '1px solid rgba(255,45,85,0.2)',
            borderRadius: '2px',
            opacity: 0, animationDelay: '0.2s',
          }}>
            <span style={{ color: '#ff2d55', fontSize: '0.75rem', fontWeight: 700, flexShrink: 0 }}>⚠ NOTICE</span>
            <span style={{ color: '#4a7a8a', fontSize: '0.7rem', lineHeight: 1.5 }}>
              Content is for <strong style={{ color: '#a8c8d8' }}>educational and defensive purposes only</strong>. Do not use these techniques against systems you don't own or have explicit permission to test. Always follow responsible disclosure practices.
            </span>
          </div>
        </div>

        {/* Search */}
        <div className="fade-in" style={{ marginBottom: '32px', opacity: 0, animationDelay: '0.25s' }}>
          <div style={{ position: 'relative' }}>
            <span style={{
              position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)',
              color: '#4a7a8a', fontSize: '0.75rem',
            }}>
              ⌕
            </span>
            <input
              type="text"
              placeholder="Search threats, vulnerabilities, techniques..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                width: '100%', maxWidth: '480px',
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                borderColor: searchQuery ? 'rgba(0,229,255,0.4)' : 'var(--border)',
                color: '#e8f4f8',
                fontSize: '0.75rem',
                padding: '10px 14px 10px 36px',
                outline: 'none',
                fontFamily: "'JetBrains Mono', monospace",
                transition: 'border-color 0.2s',
              }}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                style={{
                  position: 'absolute', right: '14px', top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', color: '#4a7a8a', cursor: 'pointer',
                  fontSize: '0.8rem',
                }}
              >
                ✕
              </button>
            )}
          </div>
          {searchQuery && (
            <div style={{ color: '#4a7a8a', fontSize: '0.65rem', marginTop: '8px' }}>
              {filtered.length} result{filtered.length !== 1 ? 's' : ''} for "{searchQuery}"
            </div>
          )}
        </div>

        {/* Section header */}
        <div className="fade-in" style={{
          display: 'flex', alignItems: 'center', gap: '16px',
          marginBottom: '24px', opacity: 0, animationDelay: '0.3s',
        }}>
          <span style={{ color: '#4a7a8a', fontSize: '0.65rem', letterSpacing: '0.2em', textTransform: 'uppercase' }}>
            SECURITY DOMAINS
          </span>
          <div style={{ flex: 1, height: '1px', background: 'var(--border)' }} />
          <span style={{ color: '#4a7a8a', fontSize: '0.65rem' }}>{filtered.length}/{categories.length}</span>
        </div>

        {/* Category grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))',
          gap: '16px',
          marginBottom: '64px',
        }}>
          {filtered.map((cat, i) => (
            <CategoryCard key={cat.id} cat={cat} index={i} />
          ))}
          {filtered.length === 0 && (
            <div style={{
              gridColumn: '1 / -1', textAlign: 'center', padding: '48px',
              color: '#4a7a8a', fontSize: '0.8rem',
            }}>
              No matching threat categories found for "{searchQuery}"
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{
          borderTop: '1px solid var(--border)',
          paddingTop: '24px',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          flexWrap: 'wrap', gap: '12px',
        }}>
          <div style={{ color: '#4a7a8a', fontSize: '0.65rem' }}>
            MIT License · <a href="https://github.com/Bd-Mutant7/Cybersecurity-Threats-Guide" target="_blank" rel="noopener noreferrer" style={{ color: '#00e5ff', textDecoration: 'none' }}>github.com/Bd-Mutant7/Cybersecurity-Threats-Guide</a>
          </div>
          <div style={{ color: '#4a7a8a', fontSize: '0.65rem' }}>
            BUILD 2.1.0 · EDUCATIONAL USE ONLY
          </div>
        </div>
      </div>
    </div>
  );
}
