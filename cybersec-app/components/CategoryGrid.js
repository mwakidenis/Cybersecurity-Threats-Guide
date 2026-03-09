'use client';
import Link from 'next/link';
import { categories } from '../lib/threats-data';

export default function CategoryGrid() {
  return (
    <section id="categories" style={{
      padding: '5rem 2rem',
      maxWidth: '1100px',
      margin: '0 auto',
      position: 'relative',
      zIndex: 1,
    }}>
      {/* Section header */}
      <div style={{ marginBottom: '3rem' }}>
        <div style={{
          fontSize: '0.7rem',
          color: 'var(--green)',
          letterSpacing: '0.25em',
          fontWeight: 600,
          marginBottom: '0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}>
          <span style={{ display: 'inline-block', width: '20px', height: '1px', background: 'var(--green)' }} />
          THREAT CATEGORIES
        </div>
        <h2 style={{
          fontFamily: 'var(--font-display)',
          fontSize: 'clamp(1.6rem, 3vw, 2.5rem)',
          fontWeight: 800,
          color: 'var(--text-bright)',
          letterSpacing: '-0.02em',
        }}>Security Domains</h2>
      </div>

      {/* Category grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
        gap: '1px',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        overflow: 'hidden',
        background: 'var(--border)',
      }}>
        {categories.map((cat) => (
          <CategoryCard key={cat.id} category={cat} />
        ))}
      </div>
    </section>
  );
}

function CategoryCard({ category }) {
  return (
    <Link
      href={`/${category.id}`}
      style={{ display: 'block' }}
    >
      <div
        style={{
          padding: '2rem',
          background: 'var(--surface)',
          height: '100%',
          transition: 'background 0.2s ease',
          cursor: 'pointer',
          position: 'relative',
          overflow: 'hidden',
        }}
        onMouseEnter={e => {
          e.currentTarget.style.background = 'var(--surface2)';
        }}
        onMouseLeave={e => {
          e.currentTarget.style.background = 'var(--surface)';
        }}
      >
        {/* Accent line */}
        <div style={{
          position: 'absolute',
          top: 0, left: 0, right: 0,
          height: '2px',
          background: category.color,
          opacity: 0.7,
        }} />

        {/* Header */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: '1.25rem',
        }}>
          <span style={{
            fontSize: '0.65rem',
            color: 'var(--text-muted)',
            letterSpacing: '0.15em',
            fontWeight: 600,
            padding: '3px 8px',
            border: '1px solid var(--border2)',
            borderRadius: '3px',
          }}>
            {category.label}
          </span>
          <span style={{
            fontSize: '1.4rem',
            color: category.color,
            lineHeight: 1,
          }}>
            {category.icon}
          </span>
        </div>

        {/* Title */}
        <h3 style={{
          fontFamily: 'var(--font-display)',
          fontSize: '1.15rem',
          fontWeight: 700,
          color: 'var(--text-bright)',
          marginBottom: '0.75rem',
          letterSpacing: '-0.01em',
        }}>
          {category.title}
        </h3>

        {/* Description */}
        <p style={{
          fontSize: '0.78rem',
          color: 'var(--text-muted)',
          lineHeight: 1.65,
          marginBottom: '1.5rem',
        }}>
          {category.description}
        </p>

        {/* Threat count + link */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <span style={{
            fontSize: '0.7rem',
            color: category.color,
            opacity: 0.8,
          }}>
            {category.threats.length} threats documented
          </span>
          <span style={{
            fontSize: '0.7rem',
            color: 'var(--text-muted)',
            letterSpacing: '0.1em',
          }}>
            EXPLORE →
          </span>
        </div>
      </div>
    </Link>
  );
}
