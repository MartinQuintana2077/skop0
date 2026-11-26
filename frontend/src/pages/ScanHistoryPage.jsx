import React, { useState, useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { getScanHistory, deleteScan, deleteBatchScans } from "../services/api";
import { useAuth } from "../context/AuthContext";
import { 
  Clock, 
  Monitor, 
  Shield, 
  FileText, 
  Calendar, 
  Search, 
  MoreVertical, 
  Trash2, 
  Check, 
  CheckSquare, 
  Square 
} from "lucide-react";

export default function ScanHistoryPage() {
  const navigate = useNavigate();
  const { getToken } = useAuth();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeMenuId, setActiveMenuId] = useState(null);
  
  // Eliminación individual
  const [scanToDelete, setScanToDelete] = useState(null);
  
  // Eliminación por lotes (múltiples burbujas)
  const [selectedScanIds, setSelectedScanIds] = useState([]);
  const [batchModalOpen, setBatchModalOpen] = useState(false);
  
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState(null);
  
  const [dateFilter, setDateFilter] = useState("all"); // 'all', 'week', 'custom'
  const [customDate, setCustomDate] = useState("");
  const [networkFilter, setNetworkFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  
  const customNetNames = useMemo(() => {
    try {
      return JSON.parse(localStorage.getItem("secscan_network_names") || "{}");
    } catch {
      return {};
    }
  }, []);

  const getFriendlyNetName = (s) => {
    let raw = s.network_name || s.target_ip || s.ip || "";
    if (!raw || raw.toLowerCase() === "auto") raw = "Red Local";
    return customNetNames[raw] || customNetNames[s.target_ip] || s.network_name || (raw.startsWith("Red") ? raw : `Red ${raw}`);
  };

  useEffect(() => {
    async function fetchHistory() {
      try {
        const token = await getToken();
        const data = await getScanHistory(token);
        if (data.status === "ok") {
          const sorted = (data.scans || []).sort((a, b) => new Date(b.timestamp || b.created_at) - new Date(a.timestamp || a.created_at));
          setScans(sorted);
        }
      } catch (err) {
        console.error("Error cargando historial", err);
      } finally {
        setLoading(false);
      }
    }
    fetchHistory();
  }, [getToken]);

  useEffect(() => {
    const handleClickOutside = () => setActiveMenuId(null);
    window.addEventListener("click", handleClickOutside);
    return () => window.removeEventListener("click", handleClickOutside);
  }, []);

  // Selección individual de una burbuja
  const handleToggleSelect = (scanId, e) => {
    if (e) e.stopPropagation();
    setSelectedScanIds(prev => 
      prev.includes(scanId) ? prev.filter(id => id !== scanId) : [...prev, scanId]
    );
  };

  // Alternar selección de todas las burbujas visibles
  const handleSelectAll = () => {
    if (selectedScanIds.length === filteredScans.length && filteredScans.length > 0) {
      setSelectedScanIds([]);
    } else {
      setSelectedScanIds(filteredScans.map(s => s.id));
    }
  };

  // Click en la tarjeta
  const handleCardClick = (scanId) => {
    if (selectedScanIds.length > 0) {
      handleToggleSelect(scanId);
    } else {
      navigate(`/history/${scanId}`);
    }
  };

  // Confirmar eliminación individual
  const handleDeleteConfirm = async () => {
    if (!scanToDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      const token = await getToken();
      const res = await deleteScan(scanToDelete.id, token);
      if (res.status === "ok") {
        setScans((prev) => prev.filter((s) => s.id !== scanToDelete.id));
        setSelectedScanIds((prev) => prev.filter((id) => id !== scanToDelete.id));
        setScanToDelete(null);
        setDeleteError(null);
      } else {
        setDeleteError("Error al eliminar la auditoría: " + (res.detail || res.message || "Error desconocido"));
      }
    } catch (err) {
      console.error("Error eliminando auditoría:", err);
      setDeleteError("Error de conexión al intentar eliminar la auditoría.");
    } finally {
      setDeleting(false);
    }
  };

  // Confirmar eliminación en lote (múltiples burbujas)
  const handleBatchDeleteConfirm = async () => {
    if (!selectedScanIds.length) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      const token = await getToken();
      const res = await deleteBatchScans(selectedScanIds, token);
      if (res.status === "ok") {
        const deletedSet = new Set(selectedScanIds);
        setScans((prev) => prev.filter((s) => !deletedSet.has(s.id)));
        setSelectedScanIds([]);
        setBatchModalOpen(false);
        setDeleteError(null);
      } else {
        setDeleteError("Error al eliminar auditorías: " + (res.detail || res.message || "Error desconocido"));
      }
    } catch (err) {
      console.error("Error en eliminación por lotes:", err);
      setDeleteError("Error de conexión al intentar eliminar las auditorías.");
    } finally {
      setDeleting(false);
    }
  };

  const availableNetworks = useMemo(() => {
    const set = new Set();
    scans.forEach(s => {
      set.add(getFriendlyNetName(s));
    });
    return Array.from(set);
  }, [scans, customNetNames]);

  const filteredScans = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return scans.filter(scan => {
      const netName = getFriendlyNetName(scan);
      if (networkFilter !== "all" && netName !== networkFilter) {
        return false;
      }

      if (q) {
        const idStr = (scan.id || scan.scan_id || "").toLowerCase();
        const ipStr = (scan.target_ip || scan.ip || "").toLowerCase();
        const netLower = (netName || "").toLowerCase();
        if (!idStr.includes(q) && !netLower.includes(q) && !ipStr.includes(q)) {
          return false;
        }
      }

      if (dateFilter === "all") return true;
      
      const now = new Date();
      const scanDate = new Date(scan.timestamp || scan.created_at);
      
      if (dateFilter === "week") {
        const diffTime = Math.abs(now - scanDate);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        return diffDays <= 7;
      }
      
      if (dateFilter === "custom" && customDate) {
        const sDateStr = scanDate.toISOString().split("T")[0];
        return sDateStr === customDate;
      }
      
      return true;
    });
  }, [scans, dateFilter, customDate, networkFilter, searchQuery]);

  const allFilteredSelected = filteredScans.length > 0 && selectedScanIds.length === filteredScans.length;

  return (
    <div className="page-container fade-in">
      <div className="history-top-bar" style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'center', marginBottom: '20px' }}>
        <button className="btn btn-back" onClick={() => navigate("/")}>
          ← Volver al Inicio
        </button>
      </div>

      <div className="results-header" style={{ marginBottom: '20px' }}>
        <h1>Auditorías Históricas</h1>
        <p>Historial de análisis y descubrimientos de red agrupados por infraestructura.</p>
      </div>

      <div className="history-filters" style={{ display: 'flex', flexWrap: 'wrap', gap: '15px', alignItems: 'center', marginBottom: '24px', background: 'var(--bg-surface)', padding: '15px 18px', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Search size={18} className="inline-icon" color="var(--purple-400)" />
          <span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-secondary)' }}>Red Auditada:</span>
        </div>

        <select 
          className="bento-select" 
          value={networkFilter} 
          onChange={(e) => setNetworkFilter(e.target.value)}
          style={{ 
            padding: '8px 14px', 
            borderRadius: '8px', 
            background: '#0b0f19', 
            border: '1px solid var(--border-base)', 
            color: '#f8fafc', 
            outline: 'none',
            fontSize: '14px',
            fontWeight: '600',
            cursor: 'pointer',
            colorScheme: 'dark'
          }}
        >
          <option value="all" style={{ background: '#0f172a', color: '#f8fafc' }}>🌐 Todas las Redes ({scans.length})</option>
          {availableNetworks.map((net, idx) => (
            <option key={idx} value={net} style={{ background: '#0f172a', color: '#f8fafc' }}>
              📡 {net}
            </option>
          ))}
        </select>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginLeft: '6px' }}>
          <Calendar size={18} className="inline-icon" color="var(--text-secondary)" />
          <span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-secondary)' }}>Fecha:</span>
        </div>
        
        <select 
          className="bento-select" 
          value={dateFilter} 
          onChange={(e) => setDateFilter(e.target.value)}
          style={{ 
            padding: '8px 14px', 
            borderRadius: '8px', 
            background: '#0b0f19', 
            border: '1px solid var(--border-base)', 
            color: '#f8fafc', 
            outline: 'none',
            fontSize: '14px',
            fontWeight: '600',
            cursor: 'pointer',
            colorScheme: 'dark'
          }}
        >
          <option value="all" style={{ background: '#0f172a', color: '#f8fafc' }}>Todas las fechas</option>
          <option value="week" style={{ background: '#0f172a', color: '#f8fafc' }}>Esta semana (Últimos 7 días)</option>
          <option value="custom" style={{ background: '#0f172a', color: '#f8fafc' }}>Fecha específica...</option>
        </select>

        {dateFilter === "custom" && (
          <input 
            type="date" 
            value={customDate}
            onChange={(e) => setCustomDate(e.target.value)}
            style={{ 
              padding: '8px 14px', 
              borderRadius: '8px', 
              background: '#0b0f19', 
              border: '1px solid var(--border-base)', 
              color: '#f8fafc', 
              outline: 'none',
              fontSize: '14px',
              fontWeight: '600',
              cursor: 'pointer',
              colorScheme: 'dark'
            }}
          />
        )}

        {/* Buscador rápido por ID de escaneo, nombre de router o IP */}
        <div
          style={{
            position: 'relative',
            display: 'flex',
            alignItems: 'center',
            flex: '1 1 240px',
            maxWidth: '340px',
          }}
        >
          <Search
            size={15}
            style={{
              position: 'absolute',
              left: '12px',
              color: 'var(--text-muted)',
              pointerEvents: 'none',
            }}
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar por ID, router o IP..."
            style={{
              width: '100%',
              padding: '8px 30px 8px 34px',
              borderRadius: '8px',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-base)',
              color: 'var(--text-primary)',
              outline: 'none',
              fontSize: '13.5px',
              fontFamily: "'Inter', sans-serif",
            }}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              title="Limpiar búsqueda"
              style={{
                position: 'absolute',
                right: '8px',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '13px',
                padding: '2px 4px',
              }}
            >
              ✕
            </button>
          )}
        </div>

        {/* Botón de selección múltiple rápida en la barra de filtros */}
        {filteredScans.length > 0 && (
          <button
            type="button"
            onClick={handleSelectAll}
            style={{
              marginLeft: 'auto',
              background: selectedScanIds.length > 0 ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255, 255, 255, 0.05)',
              border: `1px solid ${selectedScanIds.length > 0 ? '#38bdf8' : 'rgba(255, 255, 255, 0.15)'}`,
              color: selectedScanIds.length > 0 ? '#38bdf8' : '#cbd5e1',
              padding: '8px 14px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            {allFilteredSelected ? (
              <>
                <CheckSquare size={16} /> Deseleccionar Todas
              </>
            ) : (
              <>
                <Square size={16} /> Seleccionar Varias {selectedScanIds.length > 0 ? `(${selectedScanIds.length})` : ''}
              </>
            )}
          </button>
        )}
      </div>

      {/* BARRA FLOTANTE DE ACCIONES EN LOTE (Aparece cuando hay 1 o más seleccionadas) */}
      {selectedScanIds.length > 0 && (
        <div className="batch-action-bar">
          <div className="batch-action-info">
            <span className="batch-count-badge">{selectedScanIds.length}</span>
            <span>{selectedScanIds.length === 1 ? 'burbuja seleccionada' : 'burbujas seleccionadas'}</span>
          </div>
          <div className="batch-action-buttons">
            <button className="btn-batch-ghost" onClick={handleSelectAll}>
              {allFilteredSelected ? "Deseleccionar todas" : `Seleccionar todas (${filteredScans.length})`}
            </button>
            <button className="btn-batch-ghost" onClick={() => setSelectedScanIds([])}>
              Cancelar
            </button>
            <button className="btn-batch-delete" onClick={() => setBatchModalOpen(true)}>
              <Trash2 size={16} /> Eliminar {selectedScanIds.length} {selectedScanIds.length === 1 ? 'burbuja' : 'burbujas'}
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="scanning-spinner" style={{ margin: "40px auto", width: "40px", height: "40px" }} />
      ) : filteredScans.length > 0 ? (
        <div className="capsule-grid">
          {filteredScans.map((scan, i) => {
            const hasVulns = scan.vulnerabilidades_found > 0;
            const isSelected = selectedScanIds.includes(scan.id);
            return (
              <div 
                key={scan.id} 
                className={`capsule-card slide-up ${hasVulns ? 'danger' : ''} ${isSelected ? 'selected' : ''}`} 
                style={{ animationDelay: `${i * 0.03}s` }}
                onClick={() => handleCardClick(scan.id)}
              >
                <div className="capsule-header" style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: '10px' }}>
                  {/* Fila superior: Checkbox + Estado a la izquierda, menú 3 puntos a la derecha */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', width: '100%' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div 
                        className={`capsule-checkbox ${isSelected ? 'checked' : ''}`}
                        onClick={(e) => handleToggleSelect(scan.id, e)}
                        title={isSelected ? "Deseleccionar esta burbuja" : "Seleccionar esta burbuja"}
                      >
                        {isSelected && <Check size={14} color="#ffffff" strokeWidth={3.5} />}
                      </div>

                      <div className={`capsule-status ${scan.status === 'completed' ? 'completed' : (scan.status === 'error' || scan.status === 'cancelled') ? 'failed' : 'processing'}`}>
                        {scan.status === 'completed' ? 'Completado' : scan.status === 'cancelled' ? 'Cancelado' : scan.status === 'error' ? 'Fallido' : scan.status}
                      </div>
                    </div>

                    {/* Menú de 3 puntitos */}
                    <div style={{ position: 'relative', flexShrink: 0 }} onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setActiveMenuId(activeMenuId === scan.id ? null : scan.id);
                        }}
                        style={{
                          background: activeMenuId === scan.id ? 'rgba(255, 255, 255, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.12)',
                          borderRadius: '8px',
                          width: '28px',
                          height: '28px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: activeMenuId === scan.id ? '#f8fafc' : '#94a3b8',
                          cursor: 'pointer',
                          transition: 'all 0.2s ease',
                          padding: 0
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.color = '#f8fafc';
                          e.currentTarget.style.background = 'rgba(255, 255, 255, 0.12)';
                        }}
                        onMouseLeave={(e) => {
                          if (activeMenuId !== scan.id) {
                            e.currentTarget.style.color = '#94a3b8';
                            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
                          }
                        }}
                        title="Opciones de la auditoría"
                        aria-label="Opciones de la auditoría"
                      >
                        <MoreVertical size={16} />
                      </button>

                      {activeMenuId === scan.id && (
                        <div 
                          style={{
                            position: 'absolute',
                            top: '100%',
                            right: 0,
                            marginTop: '6px',
                            background: '#0d1117',
                            border: '1px solid rgba(248, 113, 113, 0.35)',
                            borderRadius: '10px',
                            boxShadow: '0 10px 25px rgba(0,0,0,0.8), 0 0 15px rgba(239, 68, 68, 0.15)',
                            zIndex: 60,
                            minWidth: '170px',
                            padding: '4px',
                            overflow: 'hidden'
                          }}
                        >
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setActiveMenuId(null);
                              setScanToDelete(scan);
                            }}
                            style={{
                              width: '100%',
                              padding: '8px 12px',
                              background: 'transparent',
                              border: 'none',
                              borderRadius: '6px',
                              color: '#f87171',
                              fontSize: '12px',
                              fontWeight: 600,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '8px',
                              cursor: 'pointer',
                              textAlign: 'left',
                              transition: 'background 0.15s ease'
                            }}
                            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(239, 68, 68, 0.15)'}
                            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                          >
                            <Trash2 size={14} /> Eliminar auditoría
                          </button>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Fila inferior: Nombre del Router/Red, Fecha y ID a ancho completo */}
                  <div style={{ minWidth: 0, width: '100%' }}>
                    <div
                      style={{
                        fontSize: '15px',
                        fontWeight: 800,
                        color: 'var(--cyan-400)',
                        marginBottom: '4px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={getFriendlyNetName(scan)}
                    >
                      📡 {getFriendlyNetName(scan)}
                    </div>
                    <div className="capsule-date" style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12.5px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '3px' }}>
                      <Clock size={13} className="inline-icon" /> 
                      {(() => {
                        if (!scan.timestamp) return "Sin fecha";
                        const isoStr = scan.timestamp.endsWith("Z") ? scan.timestamp : `${scan.timestamp}Z`;
                        try {
                          return new Date(isoStr).toLocaleString();
                        } catch (e) {
                          return new Date(scan.timestamp).toLocaleString();
                        }
                      })()}
                    </div>
                    <div className="capsule-id" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      ID: {scan.id ? scan.id.substring(0, 8) : '--------'} | Obj: {scan.target_ip || scan.ip || 'Auto'}
                    </div>
                  </div>
                </div>

                <div className="capsule-body">
                  <div className="capsule-stat">
                    <div className="capsule-stat-icon"><Monitor size={18} color="var(--accent-cyan)" /></div>
                    <div className="capsule-stat-value" style={{ color: 'var(--accent-cyan)' }}>
                      {scan.devices_found ?? '?'}
                    </div>
                    <div className="capsule-stat-label">Dispositivos</div>
                  </div>
                  
                  <div className="capsule-stat">
                    <div className="capsule-stat-icon"><Shield size={18} color={hasVulns ? 'var(--accent-red)' : 'var(--accent-green)'} /></div>
                    <div className="capsule-stat-value" style={{ color: hasVulns ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                      {scan.vulnerabilidades_found ?? '?'}
                    </div>
                    <div className="capsule-stat-label">CVEs</div>
                  </div>
                </div>


              </div>
            );
          })}
        </div>
      ) : (
        <div className="empty-state">
          <div className="empty-state-icon" style={{ marginBottom: '16px' }}><Search size={48} color="var(--text-tertiary)" className="inline-icon" /></div>
          <p>No se encontraron escaneos para los filtros seleccionados.</p>
        </div>
      )}

      {/* Modal de confirmación para eliminar auditoría INDIVIDUAL */}
      {scanToDelete && (
        <div 
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.82)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: '16px'
          }}
          onClick={() => { if (!deleting) { setScanToDelete(null); setDeleteError(null); } }}
        >
          <div 
            style={{
              backgroundColor: '#111318',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              borderRadius: '16px',
              maxWidth: '460px',
              width: '100%',
              padding: '24px',
              boxShadow: '0 25px 60px rgba(0, 0, 0, 0.85), 0 0 35px rgba(239, 68, 68, 0.12)',
              position: 'relative',
              color: '#f8fafc',
              fontFamily: "'Inter', system-ui, sans-serif"
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '16px' }}>
              <div style={{
                width: '44px',
                height: '44px',
                borderRadius: '12px',
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#f87171',
                flexShrink: 0
              }}>
                <Trash2 size={22} />
              </div>
              <div>
                <h3 style={{ fontSize: '17px', fontWeight: 800, margin: 0, color: '#f8fafc' }}>
                  ¿Eliminar esta auditoría?
                </h3>
                <p style={{ fontSize: '12px', color: '#94a3b8', margin: '3px 0 0' }}>
                  Esta acción borrará los datos permanentemente
                </p>
              </div>
            </div>

            <div style={{
              background: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '10px',
              padding: '12px 14px',
              marginBottom: '20px',
              fontSize: '12.5px',
              color: '#cbd5e1',
              lineHeight: 1.5
            }}>
              Se eliminará el registro de la auditoría de fecha <strong>{scanToDelete.timestamp ? new Date(scanToDelete.timestamp).toLocaleString() : 'Reciente'}</strong> (Objetivo: <code style={{ color: '#38bdf8' }}>{scanToDelete.target_ip || scanToDelete.ip || 'Auto'}</code>) y todos sus dispositivos detectados.
            </div>

            {deleteError && (
              <div style={{
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid rgba(239, 68, 68, 0.35)",
                color: "#f87171",
                padding: "10px 14px",
                borderRadius: "8px",
                marginBottom: "16px",
                fontSize: "12px"
              }}>
                {deleteError}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                disabled={deleting}
                onClick={() => { setScanToDelete(null); setDeleteError(null); }}
                style={{
                  background: 'transparent',
                  border: '1px solid rgba(255, 255, 255, 0.12)',
                  borderRadius: '8px',
                  padding: '9px 16px',
                  fontSize: '13px',
                  fontWeight: 600,
                  color: '#cbd5e1',
                  cursor: deleting ? 'not-allowed' : 'pointer'
                }}
              >
                Cancelar
              </button>
              <button
                type="button"
                disabled={deleting}
                onClick={handleDeleteConfirm}
                style={{
                  background: '#dc2626',
                  border: '1px solid #ef4444',
                  borderRadius: '8px',
                  padding: '9px 18px',
                  fontSize: '13px',
                  fontWeight: 700,
                  color: '#fff',
                  cursor: deleting ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  boxShadow: '0 2px 6px rgba(0, 0, 0, 0.3)'
                }}
              >
                <Trash2 size={15} />
                {deleting ? "Eliminando..." : "Sí, eliminar"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal de confirmación para eliminar EN LOTE (Múltiples burbujas) */}
      {batchModalOpen && (
        <div 
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.82)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: '16px'
          }}
          onClick={() => { if (!deleting) { setBatchModalOpen(false); setDeleteError(null); } }}
        >
          <div 
            style={{
              backgroundColor: '#111318',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              borderRadius: '16px',
              maxWidth: '480px',
              width: '100%',
              padding: '24px',
              boxShadow: '0 25px 60px rgba(0, 0, 0, 0.85), 0 0 35px rgba(239, 68, 68, 0.12)',
              position: 'relative',
              color: '#f8fafc',
              fontFamily: "'Inter', system-ui, sans-serif"
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '16px' }}>
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '12px',
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#f87171',
                flexShrink: 0
              }}>
                <Trash2 size={24} />
              </div>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 800, margin: 0, color: '#f8fafc' }}>
                  ¿Eliminar {selectedScanIds.length} {selectedScanIds.length === 1 ? 'auditoría' : 'auditorías'}?
                </h3>
                <p style={{ fontSize: '12px', color: '#94a3b8', margin: '3px 0 0' }}>
                  Esta acción no se puede deshacer
                </p>
              </div>
            </div>

            <div style={{
              background: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '10px',
              padding: '14px 16px',
              marginBottom: '20px',
              fontSize: '13px',
              color: '#cbd5e1',
              lineHeight: 1.5
            }}>
              Se eliminarán permanentemente <strong>{selectedScanIds.length}</strong> auditorías de la base de datos local y remota, junto con todos los historiales de puertos, vulnerabilidades y mapas de red asociados.
            </div>

            {deleteError && (
              <div style={{
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid rgba(239, 68, 68, 0.35)",
                color: "#f87171",
                padding: "10px 14px",
                borderRadius: "8px",
                marginBottom: "16px",
                fontSize: "12px"
              }}>
                {deleteError}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                disabled={deleting}
                onClick={() => { setBatchModalOpen(false); setDeleteError(null); }}
                style={{
                  background: 'transparent',
                  border: '1px solid rgba(255, 255, 255, 0.12)',
                  borderRadius: '8px',
                  padding: '9px 16px',
                  fontSize: '13px',
                  fontWeight: 600,
                  color: '#cbd5e1',
                  cursor: deleting ? 'not-allowed' : 'pointer'
                }}
              >
                Cancelar
              </button>
              <button
                type="button"
                disabled={deleting}
                onClick={handleBatchDeleteConfirm}
                style={{
                  background: '#dc2626',
                  border: '1px solid #ef4444',
                  borderRadius: '8px',
                  padding: '9px 18px',
                  fontSize: '13px',
                  fontWeight: 700,
                  color: '#fff',
                  cursor: deleting ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  boxShadow: '0 2px 6px rgba(0, 0, 0, 0.3)'
                }}
              >
                <Trash2 size={15} />
                {deleting ? `Eliminando (${selectedScanIds.length})...` : `Sí, eliminar ${selectedScanIds.length}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
