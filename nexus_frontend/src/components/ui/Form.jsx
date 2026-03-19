export function FormGroup({ label, children, half }) {
  return (
    <div style={{ marginBottom:14,flex:half?'1':'unset' }}>
      <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',
        letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>{label}</label>
      {children}
    </div>
  )
}

export function Input({ value, onChange, placeholder, type='text', style={} }) {
  return (
    <input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} type={type}
      style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,
        padding:'8px 12px',color:'var(--text)',fontFamily:type==='password'?'var(--mono)':'var(--ui)',
        fontSize:13,outline:'none',transition:'border-color .2s',...style }}
      onFocus={e=>e.target.style.borderColor='var(--cyan)'}
      onBlur={e=>e.target.style.borderColor='var(--border)'} />
  )
}

export function Select({ value, onChange, options, style={} }) {
  return (
    <select value={value} onChange={e=>onChange(e.target.value)}
      style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,
        padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none',...style }}>
      {options.map(o => typeof o === 'string'
        ? <option key={o} value={o}>{o}</option>
        : <option key={o.value} value={o.value}>{o.label}</option>
      )}
    </select>
  )
}

export function Textarea({ value, onChange, placeholder, rows=3 }) {
  return (
    <textarea value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} rows={rows}
      style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,
        padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none',
        resize:'vertical' }}
      onFocus={e=>e.target.style.borderColor='var(--cyan)'}
      onBlur={e=>e.target.style.borderColor='var(--border)'} />
  )
}

export function FormRow({ children }) {
  return <div style={{ display:'flex',gap:12 }}>{children}</div>
}

export function ModalFooter({ onClose, onSave, saveLabel='GUARDAR', loading=false }) {
  return (
    <div style={{ display:'flex',gap:10,justifyContent:'flex-end',paddingTop:16,
      borderTop:'1px solid var(--border)',marginTop:16 }}>
      <button onClick={onClose} style={{ padding:'7px 14px',borderRadius:3,border:'1px solid var(--border)',
        background:'transparent',color:'var(--text-dim)',cursor:'pointer',fontFamily:'var(--ui)',fontSize:12,fontWeight:600 }}>
        CANCELAR
      </button>
      <button onClick={onSave} disabled={loading}
        style={{ padding:'7px 14px',borderRadius:3,border:'1px solid var(--green)',
          background:'#00ff9d15',color:'var(--green)',cursor:'pointer',fontFamily:'var(--ui)',fontSize:12,fontWeight:600,
          opacity:loading?.6:1 }}>
        {loading ? '⟳ GUARDANDO...' : saveLabel}
      </button>
    </div>
  )
}
