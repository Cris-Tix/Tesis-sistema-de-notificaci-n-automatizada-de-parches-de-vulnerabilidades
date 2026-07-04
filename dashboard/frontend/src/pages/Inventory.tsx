import { useState, useEffect, type FormEvent, type ReactNode } from 'react'
import { api } from '../api/client'
import { usePolling } from '../hooks/usePolling'
import { TierBadge } from '../components/TierBadge'
import type { InventoryItem, PaginatedResponse } from '../types'

const LIMIT = 25

interface FormData {
  cpe_uri: string
  vendor: string
  product: string
  version: string
  asset_name: string
  ip_address: string
  criticality: string
  exposed_to_internet: boolean
  owner_team: string
  notes: string
}

const DEFAULT_FORM: FormData = {
  cpe_uri: '',
  vendor: '',
  product: '',
  version: '',
  asset_name: '',
  ip_address: '',
  criticality: 'MEDIUM',
  exposed_to_internet: false,
  owner_team: '',
  notes: '',
}

function Field({ label, children, required }: { label: string; children: ReactNode; required?: boolean }) {
  return (
    <div>
      <label className="block text-xs font-medium mb-1" style={{ color: '#9CA3AF' }}>
        {label}{required && <span style={{ color: '#F87171' }}> *</span>}
      </label>
      {children}
    </div>
  )
}

const inputCls = "w-full px-3 py-2 rounded text-sm text-white outline-none focus:ring-1 focus:ring-[#1F3A6B]"
const inputStyle = { backgroundColor: '#0A0E1A', border: '1px solid #1E2A3A' }

export function Inventory() {
  const [data, setData] = useState<PaginatedResponse<InventoryItem> | null>(null)
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [page, setPage] = useState(1)
  const [modal, setModal] = useState<'create' | 'edit' | null>(null)
  const [editItem, setEditItem] = useState<InventoryItem | null>(null)
  const [form, setForm] = useState<FormData>(DEFAULT_FORM)
  const [formError, setFormError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const fetchItems = () => {
    api.inventory({ page, limit: LIMIT, search: search || undefined })
      .then(setData)
      .catch(console.error)
  }

  usePolling(fetchItems, 30_000)
  useEffect(fetchItems, [page, search])

  const openCreate = () => {
    setForm(DEFAULT_FORM)
    setFormError(null)
    setEditItem(null)
    setModal('create')
  }

  const openEdit = (item: InventoryItem) => {
    setForm({
      cpe_uri: item.cpe_uri,
      vendor: item.vendor ?? '',
      product: item.product ?? '',
      version: item.version ?? '',
      asset_name: item.asset_name ?? '',
      ip_address: item.ip_address ?? '',
      criticality: item.criticality,
      exposed_to_internet: item.exposed_to_internet,
      owner_team: item.owner_team ?? '',
      notes: item.notes ?? '',
    })
    setFormError(null)
    setEditItem(item)
    setModal('edit')
  }

  const closeModal = () => { setModal(null); setFormError(null) }

  const doSave = async () => {
    if (!form.cpe_uri.trim()) { setFormError('CPE URI es requerido'); return }
    setSaving(true)
    setFormError(null)
    try {
      const payload = {
        ...form,
        ip_address: form.ip_address || null,
        vendor: form.vendor || null,
        product: form.product || null,
        version: form.version || null,
        asset_name: form.asset_name || null,
        owner_team: form.owner_team || null,
        notes: form.notes || null,
      }
      if (modal === 'create') await api.createInventory(payload)
      else if (editItem) await api.updateInventory(editItem.id, payload)
      closeModal()
      fetchItems()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Error al guardar')
    } finally {
      setSaving(false)
    }
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    await doSave()
  }

  const handleDelete = async (item: InventoryItem) => {
    if (!confirm(`¿Eliminar "${item.asset_name ?? item.cpe_uri}"?`)) return
    try {
      await api.deleteInventory(item.id)
      fetchItems()
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Error al eliminar')
    }
  }

  const handleSearch = () => { setSearch(searchInput); setPage(1) }

  const totalPages = data ? Math.ceil(data.total / LIMIT) : 1

  const field = (key: keyof FormData, val: string | boolean) =>
    setForm(f => ({ ...f, [key]: val }))

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Software Inventory</h1>
        <button
          onClick={openCreate}
          className="px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors hover:opacity-90"
          style={{ backgroundColor: '#1F3A6B' }}
        >
          + Agregar Asset
        </button>
      </div>

      {/* Search */}
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Buscar por vendor, product, asset o CPE..."
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          className={inputCls + ' flex-1'}
          style={inputStyle}
        />
        <button
          onClick={handleSearch}
          className="px-4 py-2 rounded text-sm font-medium text-white"
          style={{ backgroundColor: '#1F3A6B' }}
        >
          Buscar
        </button>
        {search && (
          <button
            onClick={() => { setSearch(''); setSearchInput(''); setPage(1) }}
            className="px-3 py-2 rounded text-sm"
            style={{ backgroundColor: '#1E2A3A', color: '#9CA3AF' }}
          >
            ✕
          </button>
        )}
      </div>

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ backgroundColor: '#111827', border: '1px solid #1E2A3A' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid #1E2A3A' }}>
                {['Asset', 'Vendor / Product', 'IP', 'Criticality', 'Internet', 'Equipo', 'Acciones'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#6B7280' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map(item => (
                <tr
                  key={item.id}
                  style={{ borderBottom: '1px solid #1E2A3A' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = '#162040'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = ''}
                >
                  <td className="px-4 py-3">
                    <p className="font-medium text-white">{item.asset_name ?? '—'}</p>
                    <p className="text-xs font-mono" style={{ color: '#6B7280' }}>{item.version ?? ''}</p>
                  </td>
                  <td className="px-4 py-3">
                    <p style={{ color: '#E5E7EB' }}>{item.vendor ?? '—'}</p>
                    <p className="text-xs" style={{ color: '#6B7280' }}>{item.product ?? ''}</p>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs" style={{ color: '#9CA3AF' }}>
                    {item.ip_address ?? '—'}
                  </td>
                  <td className="px-4 py-3">
                    <TierBadge tier={item.criticality} />
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span style={{ color: item.exposed_to_internet ? '#F87171' : '#6B7280' }}>
                      {item.exposed_to_internet ? '✓' : '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs" style={{ color: '#9CA3AF' }}>
                    {item.owner_team ?? '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      <button
                        onClick={() => openEdit(item)}
                        className="px-2 py-1 rounded text-xs transition-colors"
                        style={{ backgroundColor: '#1F3A6B', color: '#93C5FD' }}
                      >
                        Editar
                      </button>
                      <button
                        onClick={() => handleDelete(item)}
                        className="px-2 py-1 rounded text-xs transition-colors"
                        style={{ backgroundColor: '#2D1515', color: '#F87171' }}
                      >
                        Eliminar
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {(data?.items ?? []).length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: '#6B7280' }}>
                    Sin assets en el inventario
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="px-5 py-3 flex items-center justify-between" style={{ borderTop: '1px solid #1E2A3A' }}>
          <span className="text-xs" style={{ color: '#6B7280' }}>
            {data ? `${data.total} assets totales` : ''}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 rounded text-xs disabled:opacity-40"
              style={{ backgroundColor: '#1E2A3A', color: '#9CA3AF' }}
            >
              ← Anterior
            </button>
            <span className="px-2 py-1 text-xs" style={{ color: '#9CA3AF' }}>{page} / {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-3 py-1 rounded text-xs disabled:opacity-40"
              style={{ backgroundColor: '#1E2A3A', color: '#9CA3AF' }}
            >
              Siguiente →
            </button>
          </div>
        </div>
      </div>

      {/* Modal */}
      {modal && (
        <div
          className="fixed inset-0 flex items-center justify-center z-50 p-4"
          style={{ backgroundColor: 'rgba(0,0,0,0.7)' }}
          onClick={e => { if (e.target === e.currentTarget) closeModal() }}
        >
          <div
            className="w-full max-w-lg rounded-xl overflow-hidden flex flex-col max-h-[90vh]"
            style={{ backgroundColor: '#111827', border: '1px solid #1E2A3A' }}
          >
            <div className="px-5 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid #1E2A3A' }}>
              <h2 className="font-semibold text-white">
                {modal === 'create' ? 'Agregar Asset' : 'Editar Asset'}
              </h2>
              <button onClick={closeModal} style={{ color: '#6B7280' }}>✕</button>
            </div>

            <form onSubmit={handleSubmit} className="overflow-y-auto px-5 py-4 space-y-4 flex-1">
              {formError && (
                <p className="text-sm px-3 py-2 rounded" style={{ backgroundColor: '#2D1515', color: '#F87171' }}>
                  {formError}
                </p>
              )}

              <Field label="CPE URI" required>
                <input
                  required
                  value={form.cpe_uri}
                  onChange={e => field('cpe_uri', e.target.value)}
                  placeholder="cpe:2.3:a:vendor:product:version:..."
                  className={inputCls}
                  style={inputStyle}
                />
              </Field>

              <div className="grid grid-cols-3 gap-3">
                <Field label="Vendor">
                  <input value={form.vendor} onChange={e => field('vendor', e.target.value)} className={inputCls} style={inputStyle} />
                </Field>
                <Field label="Product">
                  <input value={form.product} onChange={e => field('product', e.target.value)} className={inputCls} style={inputStyle} />
                </Field>
                <Field label="Versión">
                  <input value={form.version} onChange={e => field('version', e.target.value)} className={inputCls} style={inputStyle} />
                </Field>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <Field label="Asset Name">
                  <input value={form.asset_name} onChange={e => field('asset_name', e.target.value)} className={inputCls} style={inputStyle} />
                </Field>
                <Field label="IP Address">
                  <input value={form.ip_address} onChange={e => field('ip_address', e.target.value)} placeholder="10.0.1.1" className={inputCls} style={inputStyle} />
                </Field>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <Field label="Criticality" required>
                  <select
                    value={form.criticality}
                    onChange={e => field('criticality', e.target.value)}
                    className={inputCls}
                    style={inputStyle}
                  >
                    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(v => (
                      <option key={v} value={v}>{v}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Owner Team">
                  <input value={form.owner_team} onChange={e => field('owner_team', e.target.value)} className={inputCls} style={inputStyle} />
                </Field>
              </div>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.exposed_to_internet}
                  onChange={e => field('exposed_to_internet', e.target.checked)}
                  className="w-4 h-4 rounded"
                />
                <span className="text-sm" style={{ color: '#9CA3AF' }}>Expuesto a Internet</span>
              </label>

              <Field label="Notas">
                <textarea
                  value={form.notes}
                  onChange={e => field('notes', e.target.value)}
                  rows={2}
                  className={inputCls}
                  style={{ ...inputStyle, resize: 'vertical' }}
                />
              </Field>
            </form>

            <div className="px-5 py-4 flex justify-end gap-3" style={{ borderTop: '1px solid #1E2A3A' }}>
              <button onClick={closeModal} className="px-4 py-2 rounded text-sm" style={{ backgroundColor: '#1E2A3A', color: '#9CA3AF' }}>
                Cancelar
              </button>
              <button
                type="button"
                onClick={doSave}
                disabled={saving}
                className="px-4 py-2 rounded text-sm font-medium text-white disabled:opacity-50"
                style={{ backgroundColor: '#1F3A6B' }}
              >
                {saving ? 'Guardando...' : 'Guardar'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
