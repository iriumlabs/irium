import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/Layout'
import Home from './pages/Home'
import BlockListPage from './pages/BlockListPage'
import BlockPage from './pages/BlockPage'
import TxPage from './pages/TxPage'
import AddressPage from './pages/AddressPage'
import AgreementsPage from './pages/AgreementsPage'
import AgreementDetailPage from './pages/AgreementDetailPage'
import SwapsPage from './pages/SwapsPage'
import MinersPage from './pages/MinersPage'

const qc = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 5000 } } })

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Home />} />
            <Route path="blocks" element={<BlockListPage />} />
            <Route path="block/height/:id" element={<BlockPage />} />
            <Route path="block/hash/:id" element={<BlockPage />} />
            <Route path="tx/:txid" element={<TxPage />} />
            <Route path="address/:address" element={<AddressPage />} />
            <Route path="agreements" element={<AgreementsPage />} />
            <Route path="agreement/:hash" element={<AgreementDetailPage />} />
            <Route path="swaps" element={<SwapsPage />} />
            <Route path="miners" element={<MinersPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
