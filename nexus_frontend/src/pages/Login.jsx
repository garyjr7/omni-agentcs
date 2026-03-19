import { useState, useEffect } from 'react'
import { useAuthStore } from '../store/authStore'
import { nexusApi } from '../api/client'

export default function Login() {
  const { setTokens } = useAuthStore()
  const [email,    setEmail]    = useState('admin@nexuspro.io')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  const submit = async (e) => {
    e?.preventDefault()
    if (!email || !password) { setError('Completa los campos'); return }
    setLoading(true); setError('')
    try {
      const { data } = await nexusApi.login(email, password)
      setTokens(data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Credenciales inválidas')
    } finally {
      setLoading(false)
    }
  }

  // Enter para submit
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Enter') submit() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [email, password])

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg-base)',
      display:'flex', alignItems:'center', justifyContent:'center',
      fontFamily:'var(--ui)' }}>

      {/* Fondo animado */}
      <div style={{ position:'fixed', inset:0, overflow:'hidden', zIndex:0, opacity:.04 }}>
        {Array.from({length:20},(_,i)=>(
          <div key={i} style={{ position:'absolute', fontFamily:'var(--mono)', fontSize:11,
            color:'var(--green)', whiteSpace:'nowrap',
            left:`${(i*7.3)%100}%`, top:`${(i*13.7)%100}%`,
            animation:`float ${8+i%4}s linear infinite`, opacity:.6 }}>
            {['01001110','11001000','00110101','10110001','NEXUS_PRO'][i%5]}
          </div>
        ))}
      </div>

      <div style={{ position:'relative', zIndex:1, width:'100%', maxWidth:420, padding:24 }}>
        {/* Logo */}
        <div style={{ textAlign:'center', marginBottom:40 }}>
          <div style={{ display:'inline-flex', alignItems:'center', justifyContent:'center',
            width:64, height:64, border:'1px solid var(--green)',
            background:'linear-gradient(135deg,#001a0d,#002a1a)',
            borderRadius:8, marginBottom:16,
            boxShadow:'0 0 30px #00ff9d25, inset 0 0 20px #00ff9d08' }}>
            <span style={{ fontFamily:'var(--display)', fontSize:22,
              color:'var(--green)', fontWeight:700, letterSpacing:2 }}>N</span>
          </div>
          <div style={{ fontFamily:'var(--display)', fontSize:24, fontWeight:700,
            color:'var(--text-bright)', letterSpacing:3 }}>NEXUS PRO</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            marginTop:6, letterSpacing:2 }}>AI OPERATIONS PLATFORM</div>
        </div>

        {/* Card */}
        <div style={{ background:'var(--bg-panel)', border:'1px solid var(--border)',
          borderRadius:6, padding:32,
          boxShadow:'0 20px 60px rgba(0,0,0,.5), 0 0 40px #00ff9d08' }}>

          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            letterSpacing:2, textTransform:'uppercase', marginBottom:24 }}>
            Acceso al Sistema
          </div>

          {/* Email */}
          <div style={{ marginBottom:16 }}>
            <label style={{ display:'block', fontFamily:'var(--mono)', fontSize:10,
              color:'var(--text-dim)', letterSpacing:1, textTransform:'uppercase', marginBottom:6 }}>
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              autoComplete="email"
              style={{ width:'100%', background:'var(--bg-base)', border:'1px solid var(--border)',
                borderRadius:3, padding:'10px 14px', color:'var(--text)',
                fontFamily:'var(--mono)', fontSize:13, outline:'none',
                transition:'border-color .2s',
                borderColor: error ? 'var(--red)' : undefined }}
              onFocus={e => e.target.style.borderColor = 'var(--green)'}
              onBlur={e => e.target.style.borderColor = 'var(--border)'}
            />
          </div>

          {/* Password */}
          <div style={{ marginBottom:24 }}>
            <label style={{ display:'block', fontFamily:'var(--mono)', fontSize:10,
              color:'var(--text-dim)', letterSpacing:1, textTransform:'uppercase', marginBottom:6 }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="current-password"
              placeholder="••••••••"
              style={{ width:'100%', background:'var(--bg-base)', border:'1px solid var(--border)',
                borderRadius:3, padding:'10px 14px', color:'var(--text)',
                fontFamily:'var(--mono)', fontSize:13, outline:'none',
                transition:'border-color .2s' }}
              onFocus={e => e.target.style.borderColor = 'var(--green)'}
              onBlur={e => e.target.style.borderColor = 'var(--border)'}
            />
          </div>

          {/* Error */}
          {error && (
            <div style={{ padding:'8px 12px', background:'#ff386015', border:'1px solid var(--red)',
              borderRadius:3, fontFamily:'var(--mono)', fontSize:11, color:'var(--red)',
              marginBottom:16 }}>
              ✗ {error}
            </div>
          )}

          {/* Submit */}
          <button
            onClick={submit}
            disabled={loading}
            style={{ width:'100%', padding:'12px', borderRadius:3, cursor: loading ? 'wait' : 'pointer',
              background: loading ? 'transparent' : 'var(--green)',
              border:`1px solid var(--green)`,
              color: loading ? 'var(--green)' : 'var(--bg-base)',
              fontFamily:'var(--mono)', fontSize:13, fontWeight:700, letterSpacing:2,
              transition:'all .2s',
              boxShadow: loading ? 'none' : '0 0 20px #00ff9d30' }}>
            {loading ? '⟳ AUTENTICANDO...' : '▶ ACCEDER'}
          </button>

          <div style={{ marginTop:20, padding:'10px 12px', background:'var(--bg-base)',
            border:'1px solid var(--border)', borderRadius:3,
            fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', lineHeight:1.8 }}>
            Default: admin@nexuspro.io / synthetic-password
          </div>
        </div>

        <div style={{ textAlign:'center', marginTop:20,
          fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)', letterSpacing:1 }}>
          NEXUS PRO · ZERO TRUST · JWT HS256
        </div>
      </div>

      <style>{`
        @keyframes float {
          0% { transform: translateY(0) translateX(0); }
          50% { transform: translateY(-20px) translateX(10px); }
          100% { transform: translateY(0) translateX(0); }
        }
        @keyframes blink { 50% { opacity: 0; } }
      `}</style>
    </div>
  )
}
