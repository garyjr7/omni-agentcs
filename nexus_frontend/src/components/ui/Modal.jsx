export default function Modal({ title, subtitle, onClose, children, width = 540 }) {
  return (
    <div onClick={e => e.target === e.currentTarget && onClose()}
      style={{ position:'fixed',inset:0,background:'rgba(2,5,8,.88)',backdropFilter:'blur(4px)',
        display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000,padding:20 }}>
      <div style={{ background:'var(--bg-panel)',border:'1px solid var(--border)',borderRadius:6,
        padding:24,width,maxWidth:'95vw',maxHeight:'90vh',overflowY:'auto',
        animation:'fadeIn .2s ease' }}>
        <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:16 }}>
          <div>
            <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-bright)',letterSpacing:1 }}>{title}</div>
            {subtitle && <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:3 }}>{subtitle}</div>}
          </div>
          <button onClick={onClose} style={{ background:'none',border:'none',color:'var(--text-dim)',cursor:'pointer',fontSize:18,lineHeight:1,padding:'0 4px' }}>✕</button>
        </div>
        {children}
      </div>
    </div>
  )
}
