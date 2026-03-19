// ── Reusable UI primitives ────────────────────────────────────

export function Card({ children, className = '', style = {} }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 4,
      padding: 16,
      ...style,
    }} className={className}>
      {children}
    </div>
  )
}

export function CardTitle({ children }) {
  return (
    <div style={{
      fontFamily: 'var(--mono)', fontSize: 10,
      color: 'var(--text-dim)', letterSpacing: 2,
      textTransform: 'uppercase', marginBottom: 8,
    }}>
      {children}
    </div>
  )
}

export function MetricCard({ label, value, sub, color = 'var(--green)', barPct }) {
  return (
    <Card>
      <CardTitle>{label}</CardTitle>
      <div style={{ fontFamily: 'var(--display)', fontSize: 28, fontWeight: 700, color, lineHeight: 1 }}>
        {value}
      </div>
      {sub && <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>{sub}</div>}
      {barPct !== undefined && (
        <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, marginTop: 10, overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${barPct}%`, background: color, borderRadius: 2, transition: 'width 1s ease' }} />
        </div>
      )}
    </Card>
  )
}

export function Badge({ children, color = 'var(--text-dim)', bg = 'transparent' }) {
  return (
    <span style={{
      fontFamily: 'var(--mono)', fontSize: 9,
      padding: '2px 7px', borderRadius: 10,
      border: `1px solid ${color}`, color,
      background: bg,
    }}>
      {children}
    </span>
  )
}

export function Dot({ color = 'var(--green)', size = 7 }) {
  return (
    <span style={{
      display: 'inline-block',
      width: size, height: size, borderRadius: '50%',
      background: color,
      boxShadow: `0 0 6px ${color}`,
      animation: 'pulse 2s infinite',
      flexShrink: 0,
    }} />
  )
}

export function Btn({ children, variant = 'primary', onClick, style = {} }) {
  const variants = {
    primary: { border: '1px solid var(--green)', color: 'var(--green)', background: '#00ff9d15' },
    cyan:    { border: '1px solid var(--cyan)',  color: 'var(--cyan)',  background: '#00d4ff15' },
    danger:  { border: '1px solid var(--red)',   color: 'var(--red)',   background: '#ff386015' },
    warn:    { border: '1px solid var(--yellow)',color: 'var(--yellow)',background: '#ffc10715' },
    ghost:   { border: '1px solid var(--border)',color: 'var(--text-dim)', background: 'transparent' },
  }
  return (
    <button onClick={onClick} style={{
      padding: '7px 14px', borderRadius: 3,
      fontFamily: 'var(--ui)', fontSize: 12, fontWeight: 600,
      letterSpacing: 1, cursor: 'pointer',
      display: 'inline-flex', alignItems: 'center', gap: 6,
      transition: 'all .2s',
      ...variants[variant],
      ...style,
    }}>
      {children}
    </button>
  )
}

export function SectionTitle({ children, style = {} }) {
  return (
    <div style={{
      fontFamily: 'var(--mono)', fontSize: 10,
      color: 'var(--text-dim)', letterSpacing: 2,
      textTransform: 'uppercase', ...style,
    }}>
      {children}
    </div>
  )
}

export function StatusBadge({ status }) {
  const map = {
    running:   { color: 'var(--green)',  label: 'RUNNING'  },
    idle:      { color: 'var(--text-dim)',label: 'IDLE'    },
    error:     { color: 'var(--red)',    label: 'ERROR'    },
    failed:    { color: 'var(--red)',    label: 'FAILED'   },
    completed: { color: 'var(--cyan)',   label: 'DONE'     },
    pending:   { color: 'var(--yellow)', label: 'PENDING'  },
    ok:        { color: 'var(--green)',  label: 'OK'       },
    degraded:  { color: 'var(--yellow)', label: 'DEGRADED' },
  }
  const s = map[status?.toLowerCase()] || { color: 'var(--text-dim)', label: status?.toUpperCase() || '?' }
  return <Badge color={s.color}>{s.label}</Badge>
}
export { default as Modal } from './Modal'
export { FormGroup, Input, Select, Textarea, FormRow, ModalFooter } from './Form'
