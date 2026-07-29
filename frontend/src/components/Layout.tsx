import { Link, Outlet, useLocation } from 'react-router'
import SearchBar from './SearchBar'
import StatusBar from './StatusBar'

const NAV = [
  { to: '/blocks', label: 'Blocks' },
  { to: '/miners', label: 'Miners' },
  { to: '/agreements', label: 'Agreements' },
  { to: '/swaps', label: 'Swaps' },
]

export default function Layout() {
  const { pathname } = useLocation()
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header style={{
        position: 'sticky', top: 0, zIndex: 50,
        borderBottom: '1px solid rgba(110,198,255,0.08)',
        background: 'rgba(8,11,22,0.95)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
      }}>
        <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', height: 60, display: 'flex', alignItems: 'center', gap: 20 }}>
          <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: 8, textDecoration: 'none', flexShrink: 0 }}>
            <img src="/irium-logo.png" alt="Irium" style={{ height: 30, width: 30, borderRadius: '50%', objectFit: 'cover' }} />
            <span style={{ fontSize: 13, fontWeight: 800, color: '#d4eeff', letterSpacing: '0.06em' }}>IRIUM</span>
            <span style={{ fontSize: 13, fontWeight: 400, color: 'rgba(255,255,255,0.35)', letterSpacing: '0.04em' }}>Explorer</span>
          </Link>

          <nav style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            {NAV.map(({ to, label }) => {
              const active = to === '/blocks'
                ? pathname === '/blocks'
                : pathname.startsWith(to)
              return (
                <Link
                  key={to}
                  to={to}
                  style={{
                    padding: '5px 12px',
                    borderRadius: 6,
                    fontSize: 13,
                    fontWeight: 600,
                    textDecoration: 'none',
                    border: '1px solid',
                    transition: 'all 0.15s',
                    ...(active ? {
                      background: 'linear-gradient(135deg, rgba(110,198,255,0.20), rgba(167,139,250,0.14))',
                      borderColor: 'rgba(110,198,255,0.40)',
                      color: '#d4eeff',
                    } : {
                      background: 'transparent',
                      borderColor: 'transparent',
                      color: 'rgba(255,255,255,0.35)',
                    }),
                  }}
                >
                  {label}
                </Link>
              )
            })}
          </nav>

          <div style={{ marginLeft: 'auto', width: 280 }}>
            <SearchBar />
          </div>
        </div>
      </header>

      <main style={{ flex: 1, maxWidth: 1280, margin: '0 auto', width: '100%', padding: '32px 24px' }}>
        <Outlet />
      </main>

      <StatusBar />
    </div>
  )
}
