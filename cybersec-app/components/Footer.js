export default function Footer() {
  return (
    <footer style={{
      borderTop: '1px solid var(--border)',
      padding: '2rem',
      position: 'relative',
      zIndex: 1,
    }}>
      <div style={{
        maxWidth: '1100px',
        margin: '0 auto',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem',
      }}>
        <div style={{
          fontSize: '0.7rem',
          color: 'var(--text-muted)',
          letterSpacing: '0.05em',
        }}>
          <span style={{ color: 'var(--green)' }}>CTVG</span>{' '}
          — Cybersecurity Threats &amp; Vulnerabilities Guide
        </div>
        <div style={{
          display: 'flex',
          gap: '1.5rem',
          fontSize: '0.7rem',
          color: 'var(--text-muted)',
        }}>
          <a
            href="https://github.com/Bd-Mutant7/Cybersecurity-Threats-Guide/blob/main/CONTRIBUTING.md"
            target="_blank"
            rel="noopener noreferrer"
            style={{ transition: 'color 0.2s' }}
            onMouseEnter={e => e.currentTarget.style.color = 'var(--green)'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
          >
            Contributing
          </a>
          <a
            href="https://github.com/Bd-Mutant7/Cybersecurity-Threats-Guide"
            target="_blank"
            rel="noopener noreferrer"
            style={{ transition: 'color 0.2s' }}
            onMouseEnter={e => e.currentTarget.style.color = 'var(--green)'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
          >
            GitHub
          </a>
          <span style={{ color: 'var(--border2)' }}>MIT License</span>
        </div>
      </div>
    </footer>
  );
}
