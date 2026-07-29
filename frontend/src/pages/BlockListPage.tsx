import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { api } from '../api'
import HashLink from '../components/HashLink'
import { satToIrm, timeAgo } from '../lib/fmt'

const PAGE = 50

const TH: React.CSSProperties = {
  padding: '8px 14px',
  fontSize: 9.5,
  fontWeight: 700,
  textTransform: 'uppercase',
  letterSpacing: '0.13em',
  color: 'rgba(110,198,255,0.40)',
  textAlign: 'left',
  whiteSpace: 'nowrap',
}

export default function BlockListPage() {
  const [page, setPage] = useState(0)
  const { data: blocks, isLoading } = useQuery({
    queryKey: ['blocks-list', page],
    queryFn: () => api.blocks(PAGE, page * PAGE),
    refetchInterval: 10_000,
  })
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <h1 style={{ fontSize: 22, fontWeight: 800, color: '#eef0ff', margin: 0, letterSpacing: '-0.01em' }}>Blocks</h1>

      <div style={{
        background: 'var(--bg-elev-1)',
        border: '1px solid rgba(110,198,255,0.10)',
        borderRadius: 8,
        overflow: 'hidden',
      }}>
        <div style={{ overflowX: 'auto' }}>
          {isLoading ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'rgba(255,255,255,0.25)', fontSize: 13 }}>Loading...</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(110,198,255,0.08)' }}>
                  <th style={TH}>HEIGHT</th>
                  <th style={TH}>AGE</th>
                  <th style={{ ...TH, minWidth: 200 }}>HASH</th>
                  <th style={{ ...TH, textAlign: 'center' }}>TXS</th>
                  <th style={TH}>MINER</th>
                  <th style={{ ...TH, textAlign: 'right' }}>REWARD</th>
                </tr>
              </thead>
              <tbody>
                {blocks?.map(b => (
                  <tr
                    key={b.height}
                    style={{ borderBottom: '1px solid rgba(110,198,255,0.05)' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'rgba(110,198,255,0.04)' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent' }}
                  >
                    <td style={{ padding: "9px 14px" }}>
                      <Link
                        to={`/block/height/${b.height}`}
                        style={{ fontSize: 13, fontWeight: 800, color: '#6ec6ff', textDecoration: 'none', fontFamily: "'Space Grotesk', sans-serif" }}
                      >
                        {b.height.toLocaleString()}
                      </Link>
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 11, color: 'rgba(255,255,255,0.30)', whiteSpace: 'nowrap' }}>
                      {timeAgo(b.timestamp)}
                    </td>
                    <td style={{ padding: "9px 14px", minWidth: 200 }}>
                      <HashLink hash={b.hash} to={`/block/hash/${b.hash}`} start={10} end={8} />
                    </td>
                    <td style={{ padding: "9px 14px", textAlign: 'center' }}>
                      <span style={{ fontSize: 12, color: 'rgba(110,198,255,0.65)', fontFamily: "'JetBrains Mono', monospace" }}>
                        {b.tx_count}
                      </span>
                    </td>
                    <td style={{ padding: "9px 14px" }}>
                      {b.miner_address
                        ? <HashLink hash={b.miner_address} to={`/address/${b.miner_address}`} start={5} end={4} />
                        : <span style={{ color: 'rgba(255,255,255,0.20)' }}>—</span>}
                    </td>
                    <td style={{ padding: "9px 14px", textAlign: 'right' }}>
                      <span style={{ fontSize: 11, color: '#34d399', fontFamily: "'JetBrains Mono', monospace", fontWeight: 500, whiteSpace: 'nowrap' }}>
                        {satToIrm(b.total_reward)} IRM
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px',
          borderTop: '1px solid rgba(110,198,255,0.08)',
        }}>
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 14px', borderRadius: 6,
              background: 'rgba(110,198,255,0.08)',
              border: '1px solid rgba(110,198,255,0.14)',
              color: page === 0 ? 'rgba(255,255,255,0.20)' : '#6ec6ff',
              fontSize: 12, fontWeight: 600,
              cursor: page === 0 ? 'not-allowed' : 'pointer',
              fontFamily: "'Space Grotesk', sans-serif",
            }}
          >
            <ChevronLeft size={13} /> Newer
          </button>
          <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.30)', fontFamily: "'JetBrains Mono', monospace" }}>
            Page {page + 1}
          </span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={!blocks || blocks.length < PAGE}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 14px', borderRadius: 6,
              background: 'rgba(110,198,255,0.08)',
              border: '1px solid rgba(110,198,255,0.14)',
              color: (!blocks || blocks.length < PAGE) ? 'rgba(255,255,255,0.20)' : '#6ec6ff',
              fontSize: 12, fontWeight: 600,
              cursor: (!blocks || blocks.length < PAGE) ? 'not-allowed' : 'pointer',
              fontFamily: "'Space Grotesk', sans-serif",
            }}
          >
            Older <ChevronRight size={13} />
          </button>
        </div>
      </div>
    </div>
  )
}
