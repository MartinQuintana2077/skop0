import React, { useState } from "react";
import { exportBackup, importBackup } from "../services/api";

export default function BackupModal({ isOpen, onClose, token, onRestoreSuccess }) {
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);
  const [isError, setIsError] = useState(false);

  if (!isOpen) return null;

  const handleExport = async () => {
    setLoading(true);
    setStatusMsg(null);
    setIsError(false);
    try {
      const backupData = await exportBackup(token);
      const jsonStr = JSON.stringify(backupData, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const dateStr = new Date().toISOString().slice(0, 10);
      
      const link = document.createElement("a");
      link.href = url;
      link.download = `skop0_backup_${dateStr}.skop0`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      setStatusMsg("Copia de seguridad exportada correctamente.");
    } catch (err) {
      setIsError(true);
      setStatusMsg("Error al exportar la copia de seguridad: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setLoading(true);
    setStatusMsg(null);
    setIsError(false);

    try {
      const text = await file.text();
      const payload = JSON.parse(text);
      const result = await importBackup(payload, token);

      const totalScans = result.imported_scans ?? result.restaurados?.escaneos ?? 0;
      const totalDevs = result.imported_devices ?? result.restaurados?.dispositivos ?? 0;
      const totalVulns = result.imported_vulnerabilities ?? result.restaurados?.vulnerabilidades ?? 0;

      setStatusMsg(
        `¡Restauración exitosa! Se importaron ${totalScans} auditoría(s), ` +
        `${totalDevs} dispositivo(s) y ${totalVulns} vulnerabilidad(es). Actualizando aplicación...`
      );

      setTimeout(() => {
        if (onRestoreSuccess) {
          onRestoreSuccess();
        }
      }, 2500);
    } catch (err) {
      setIsError(true);
      setStatusMsg("Error al importar la copia de seguridad: " + err.message);
    } finally {
      setLoading(false);
      e.target.value = "";
    }
  };

  return (
    <div 
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.78)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '16px'
      }}
      onClick={onClose}
    >
      <div 
        style={{
          backgroundColor: '#111318',
          border: '1px solid rgba(56, 189, 248, 0.28)',
          borderRadius: '16px',
          maxWidth: '520px',
          width: '100%',
          padding: '28px',
          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.85), 0 0 35px rgba(14, 165, 233, 0.08)',
          position: 'relative',
          color: '#f8fafc',
          fontFamily: "'Inter', system-ui, sans-serif"
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '16px',
            right: '16px',
            background: 'rgba(255, 255, 255, 0.05)',
            border: 'none',
            color: '#94a3b8',
            cursor: 'pointer',
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '18px',
            fontWeight: 'bold',
            transition: 'background 0.2s, color 0.2s'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.12)';
            e.currentTarget.style.color = '#fff';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
            e.currentTarget.style.color = '#94a3b8';
          }}
          aria-label="Cerrar"
        >
          ✕
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '22px' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: '12px',
            background: 'rgba(14, 165, 233, 0.12)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '22px',
            flexShrink: 0
          }}>
            💾
          </div>
          <div>
            <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#f8fafc', margin: 0 }}>
              Gestor de Copias de Seguridad
            </h3>
            <p style={{ fontSize: '12px', color: '#94a3b8', margin: '4px 0 0' }}>
              Exporta tus datos locales para respaldarlos o impórtalos en otra computadora.
            </p>
          </div>
        </div>

        {statusMsg && (
          <div style={{
            marginBottom: '18px',
            padding: '12px 14px',
            borderRadius: '10px',
            fontSize: '12.5px',
            lineHeight: 1.5,
            background: isError ? 'rgba(239, 68, 68, 0.12)' : 'rgba(74, 222, 128, 0.12)',
            border: `1px solid ${isError ? 'rgba(239, 68, 68, 0.35)' : 'rgba(74, 222, 128, 0.35)'}`,
            color: isError ? '#fca5a5' : '#86efac'
          }}>
            {statusMsg}
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', margin: '20px 0' }}>
          <div style={{
            padding: '16px',
            borderRadius: '12px',
            border: '1px solid rgba(56, 189, 248, 0.2)',
            background: 'rgba(14, 165, 233, 0.04)'
          }}>
            <h4 style={{ fontSize: '14px', fontWeight: 700, color: '#38bdf8', margin: '0 0 4px' }}>
              Exportar Copia de Seguridad
            </h4>
            <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 12px', lineHeight: 1.5 }}>
              Descarga un archivo <code style={{ color: '#7dd3fc', background: 'rgba(14, 165, 233, 0.15)', padding: '2px 6px', borderRadius: '4px', fontFamily: "'Fira Code', monospace" }}>.skop0</code> con todo tu historial de auditorías, dispositivos y vulnerabilidades locales.
            </p>
            <button
              onClick={handleExport}
              disabled={loading}
              style={{
                width: '100%',
                padding: '10px 16px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #0284c7, #0ea5e9)',
                border: 'none',
                color: '#fff',
                fontSize: '13px',
                fontWeight: 700,
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.6 : 1,
                boxShadow: '0 4px 15px rgba(2, 132, 199, 0.3)',
                transition: 'opacity 0.2s'
              }}
            >
              📥 Descargar Backup (.skop0)
            </button>
          </div>

          <div style={{
            padding: '16px',
            borderRadius: '12px',
            border: '1px solid rgba(245, 158, 11, 0.2)',
            background: 'rgba(245, 158, 11, 0.04)'
          }}>
            <h4 style={{ fontSize: '14px', fontWeight: 700, color: '#fbbf24', margin: '0 0 4px' }}>
              Importar Copia de Seguridad
            </h4>
            <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 12px', lineHeight: 1.5 }}>
              Carga un archivo de respaldo previo para restaurar o migrar tu información local a esta máquina.
            </p>
            <label style={{
              width: '100%',
              padding: '10px 16px',
              borderRadius: '8px',
              background: 'rgba(255, 255, 255, 0.07)',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: '#f8fafc',
              fontSize: '13px',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              textAlign: 'center'
            }}>
              📤 Seleccionar Archivo (.skop0 / .secscan)
              <input
                type="file"
                accept=".skop0,.secscan,.json"
                onChange={handleFileChange}
                disabled={loading}
                style={{ display: 'none' }}
              />
            </label>
          </div>
        </div>

        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          paddingTop: '16px',
          borderTop: '1px solid rgba(255, 255, 255, 0.08)'
        }}>
          <button
            onClick={onClose}
            style={{
              padding: '8px 20px',
              borderRadius: '8px',
              background: 'rgba(255, 255, 255, 0.08)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: '#cbd5e1',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'background 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.14)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)'}
          >
            Cerrar
          </button>
        </div>
      </div>
    </div>
  );
}
