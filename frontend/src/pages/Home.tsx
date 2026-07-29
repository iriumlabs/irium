import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { Layers, Coins, Zap, Users, Database, Activity } from 'lucide-react'
import { api } from '../api'
import StatCard from '../components/StatCard'
import HashLink from '../components/HashLink'
import MiningCalculatorCard from '../components/MiningCalculatorCard'
import { satToIrm, timeAgo, fmtHashrate, fmtAvgBlockTime } from '../lib/fmt'

function fmtSupply(height: number): string {
  const irm = height * 50
  if (irm >= 1_000_000) return `${(irm / 1_000_000).toFixed(2)}M IRM`
  if (irm >= 1_000) return `${(irm / 1_000).toFixed(1)}K IRM`
  return `${irm} IRM`
}

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

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
      <span style={{ fontSize: 10, fontWeight: 700, color: 'rgba(110,198,255,0.55)', textTransform: 'uppercase', letterSpacing: '0.16em', whiteSpace: 'nowrap' }}>
        {children}
      </span>
      <div style={{ flex: 1, height: 1, background: 'rgba(110,198,255,0.08)' }} />
    </div>
  )
}

type Tab = 'overview' | 'richlist' | 'poolstats'

export default function Home() {
  const [tab, setTab] = useState<Tab>('overview')

  const { data: blocks, isLoading } = useQuery({
    queryKey: ['home-blocks'],
    queryFn: () => api.blocks(20),
    refetchInterval: 10_000,
  })

  const { data: blockDetail } = useQuery({
    queryKey: ['home-latest-detail', blocks?.[0]?.height],
    queryFn: () => api.blockByHeight(blocks![0].height),
    enabled: !!blocks?.[0],
    staleTime: 15_000,
  })

  const { data: poolStats } = useQuery({
    queryKey: ['pool-stats'],
    queryFn: () => api.poolStats(),
    refetchInterval: 30_000,
    retry: 1,
  })

  const { data: miners } = useQuery({
    queryKey: ['miners-home'],
    queryFn: () => api.miners(500),
    staleTime: 60_000,
  })

  const { data: agreements } = useQuery({
    queryKey: ['agreements-home'],
    queryFn: () => api.agreements(1000),
    staleTime: 60_000,
  })

  const { data: htlcs } = useQuery({
    queryKey: ['htlcs-home'],
    queryFn: () => api.htlcs(500),
    staleTime: 60_000,
  })

  const latest = blocks?.[0]
  const height = latest?.height ?? 0
  // `/pool/stats` serves neither an `asic` object nor `total_miners` (verified against the live
  // endpoint). `chain_active_miners_window` is the real count of miners producing in the recent
  // window. `pool_hashrate` IS served but currently returns a physically impossible magnitude,
  // so the hashrate tile stays blank rather than displaying a number that cannot be true.
  const hashrate = 0
  const activeMinerPool = poolStats?.chain_active_miners_window ?? null
  const totalMiners = miners?.length ?? null
  const totalSupply = fmtSupply(height)
  const difficulty = blockDetail?.difficulty ?? '—'
  const avgBlockTime = height > 0 ? fmtAvgBlockTime(height) : '—'

  const TABS: { key: Tab; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'richlist', label: 'Rich List' },
    { key: 'poolstats', label: 'Pool Stats' },
  ]

  const tabBtn = (key: Tab): React.CSSProperties => ({
    padding: '6px 16px',
    borderRadius: 6,
    fontSize: 12,
    fontWeight: 600,
    border: '1px solid',
    cursor: 'pointer',
    transition: 'all 0.15s',
    fontFamily: "'Space Grotesk', sans-serif",
    background: tab === key
      ? 'linear-gradient(135deg, rgba(110,198,255,0.20), rgba(167,139,250,0.14))'
      : 'transparent',
    borderColor: tab === key ? 'rgba(110,198,255,0.40)' : 'rgba(255,255,255,0.06)',
    color: tab === key ? '#d4eeff' : 'rgba(255,255,255,0.35)',
  })

  const summaryRows = [
    { label: 'Chain Started', value: 'Jan 5, 2026', mono: false, accent: false },
    { label: 'Avg Block Time', value: avgBlockTime, mono: true, accent: false },
    { label: 'Total Blocks', value: height ? height.toLocaleString() : '—', mono: true, accent: false },
    { label: 'Total Miners', value: totalMiners !== null ? totalMiners.toLocaleString() : '—', mono: true, accent: false },
    { label: 'Agreements', value: agreements !== undefined ? agreements.length.toLocaleString() : '—', mono: true, accent: false },
    { label: 'Atomic Swaps', value: htlcs !== undefined ? htlcs.length.toLocaleString() : '—', mono: true, accent: false },
    { label: 'Coins Issued', value: height ? totalSupply : '—', mono: true, accent: true },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Tab strip */}
      <div style={{ display: 'flex', gap: 8 }}>
        {TABS.map(t => (
          <button key={t.key} style={tabBtn(t.key)} onClick={() => setTab(t.key)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab !== 'overview' && (
        <div style={{
          background: 'var(--bg-elev-1)', border: '1px solid rgba(110,198,255,0.10)',
          borderRadius: 8, padding: '40px 24px', textAlign: 'center',
          color: 'rgba(255,255,255,0.30)', fontSize: 13,
        }}>
          {tab === 'richlist' ? 'Rich List — coming soon' : 'Pool Stats — coming soon'}
        </div>
      )}

      {tab === 'overview' && (
        <>
          {/* Stat Cards */}
          <div>
            <SectionLabel>Network Stats</SectionLabel>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
              <StatCard label="Best Block" value={height ? height.toLocaleString() : '—'} sub="syncing live" icon={<Layers size={14} />} />
              <StatCard label="Block Reward" value={latest ? `${satToIrm(latest.total_reward)} IRM` : '—'} sub="per block" icon={<Coins size={14} />} />
              <StatCard label="Network Hashrate" value={poolStats ? fmtHashrate(hashrate) : '—'} sub="pool estimate" icon={<Zap size={14} />} />
              <StatCard label="Active Miners" value={activeMinerPool !== null ? String(activeMinerPool) : '—'} sub="on pool now" icon={<Users size={14} />} />
              <StatCard label="Total Supply" value={height ? totalSupply : '—'} sub="mined to date" icon={<Database size={14} />} />
              <StatCard label="Difficulty" value={difficulty !== '—' ? `0x${difficulty}` : '—'} sub="compact target" icon={<Activity size={14} />} />
            </div>
          </div>

          {/* Mining Calculator + Network Summary */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
            <MiningCalculatorCard
              networkHashrate={hashrate}
              blockReward={latest ? parseFloat(satToIrm(latest.total_reward)) : 50}
            />
            <div style={{
              background: 'var(--bg-elev-1)',
              border: '1px solid rgba(110,198,255,0.10)',
              borderRadius: 8,
              padding: '18px 20px',
            }}>
              <SectionLabel>Network Summary</SectionLabel>
              <div>
                {summaryRows.map((row, i) => (
                  <div key={row.label} style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '7px 0',
                    borderBottom: i < summaryRows.length - 1 ? '1px solid rgba(110,198,255,0.06)' : 'none',
                  }}>
                    <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', fontWeight: 500 }}>{row.label}</span>
                    <span style={{
                      fontSize: 12, fontWeight: 600,
                      color: row.accent ? '#34d399' : '#eef0ff',
                      fontFamily: row.mono ? "'JetBrains Mono', monospace" : 'inherit',
                    }}>{row.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Latest Blocks */}
          <div>
            <SectionLabel>Latest Blocks</SectionLabel>
            <div style={{
              background: 'var(--bg-elev-1)',
              border: '1px solid rgba(110,198,255,0.10)',
              borderRadius: 8,
              overflow: 'hidden',
            }}>
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '11px 16px',
                borderBottom: '1px solid rgba(110,198,255,0.08)',
              }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: 'rgba(110,198,255,0.55)', textTransform: 'uppercase', letterSpacing: '0.13em' }}>
                  Latest Blocks
                </span>
                <Link to="/blocks" style={{ fontSize: 11, color: '#6ec6ff', textDecoration: 'none', fontWeight: 600 }}>
                  View all →
                </Link>
              </div>

              <div style={{ overflowX: 'auto' }}>
                {isLoading ? (
                  <div style={{ padding: '40px', textAlign: 'center', color: 'rgba(255,255,255,0.25)', fontSize: 13 }}>Loading...</div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid rgba(110,198,255,0.08)' }}>
                        <th style={TH}>HEIGHT</th>
                        <th style={{ ...TH, minWidth: 180 }}>HASH</th>
                        <th style={TH}>AGE</th>
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
                          <td style={{ padding: '10px 14px' }}>
                            <Link
                              to={`/block/height/${b.height}`}
                              style={{ fontSize: 13, fontWeight: 800, color: '#6ec6ff', textDecoration: 'none', fontFamily: "'Space Grotesk', sans-serif" }}
                            >
                              {b.height.toLocaleString()}
                            </Link>
                          </td>
                          <td style={{ padding: '10px 14px', minWidth: 180 }}>
                            <HashLink hash={b.hash} to={`/block/hash/${b.hash}`} start={10} end={8} />
                          </td>
                          <td style={{ padding: '10px 14px', fontSize: 11, color: 'rgba(255,255,255,0.30)', whiteSpace: 'nowrap' }}>
                            {timeAgo(b.timestamp)}
                          </td>
                          <td style={{ padding: '10px 14px', textAlign: 'center' }}>
                            <span style={{ fontSize: 12, color: 'rgba(110,198,255,0.65)', fontFamily: "'JetBrains Mono', monospace" }}>
                              {b.tx_count}
                            </span>
                          </td>
                          <td style={{ padding: '10px 14px' }}>
                            {b.miner_address
                              ? <HashLink hash={b.miner_address} to={`/address/${b.miner_address}`} start={6} end={4} />
                              : <span style={{ color: 'rgba(255,255,255,0.20)' }}>—</span>}
                          </td>
                          <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                            <span style={{ fontSize: 11, color: '#34d399', fontFamily: "'JetBrains Mono', monospace", fontWeight: 500 }}>
                              {satToIrm(b.total_reward)} IRM
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
