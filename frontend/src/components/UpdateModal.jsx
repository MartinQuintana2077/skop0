import React, { useState, useEffect, useRef } from "react";
import { RefreshCw, ExternalLink, AlertTriangle, CheckCircle, Rocket, Shield } from "lucide-react";
import { startUpdateDownload, getUpdateProgress, applyAppUpdate } from "../services/api";

export default function UpdateModal({
  isOpen,
  onClose,
  updateInfo,
  onRefreshCheck,
  checkingUpdate,
  token,
}) {
  const [dlState, setDlState] = useState("idle"); // idle | downloading | ready | installing | error
  const [progress, setProgress] = useState(0);
  const [dlMb, setDlMb] = useState(0);
  const [totalMb, setTotalMb] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");
  const pollRef = useRef(null);

  useEffect(() => {
    if (!isOpen) {
      if (pollRef.current) clearInterval(pollRef.current);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const currentVer = updateInfo?.current_version || "1.3.0";
  const latestVer = updateInfo?.latest_version || currentVer;
  const isAvailable = Boolean(updateInfo?.update_available);
  const isMandatory = Boolean(updateInfo?.mandatory);
  const hasDirectExe = Boolean(updateInfo?.has_direct_exe);
  const releaseNotes = updateInfo?.release_notes || "Mejoras de estabilidad, detección de red y seguridad.";
  const downloadUrl = "/api/download-installer";

  const handleStartAutoUpdate = async () => {
    if (!hasDirectExe) {
      window.open(downloadUrl, "_blank");
      return;
    }

    setErrorMsg("");
    setDlState("downloading");
    setProgress(0);

    try {
      const res = await startUpdateDownload(
        {
          download_url: updateInfo.download_url,
          asset_name: updateInfo.asset_name,
          latest_version: latestVer,
        },
        token
      );

      if (res.status === "error") {
        setDlState("error");
        setErrorMsg(res.message || "No se pudo iniciar la descarga.");
        return;
      }

      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(async () => {
        try {
          const st = await getUpdateProgress(token);
          if (!st) return;

          setProgress(st.progress || 0);
          setDlMb(st.downloaded_mb || 0);
          setTotalMb(st.total_mb || updateInfo?.asset_size_mb || 0);

          if (st.status === "ready") {
            clearInterval(pollRef.current);
            setDlState("installing");
            await applyAppUpdate(token);
            setTimeout(() => {
              try {
                window.open("", "_self");
                window.close();
              } catch (e) {}
            }, 250);
          } else if (st.status === "error") {
            clearInterval(pollRef.current);
            setDlState("error");
            setErrorMsg(st.error || "Se interrumpió la descarga.");
          }
        } catch (err) {
          console.warn("Error consultando progreso de actualización:", err);
        }
      }, 450);
    } catch (e) {
      setDlState("error");
      setErrorMsg("Error de conexión con el motor local de actualización.");
    }
  };

  const canClose = !isAvailable && dlState !== "downloading" && dlState !== "installing";

  return (
    <div
      className="modal-overlay"
      onClick={() => canClose && onClose()}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(6, 8, 15, 0.85)",
        backdropFilter: "blur(8px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 9999,
        padding: "20px",
      }}
    >
      <div
        className="modal-content fade-in"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "linear-gradient(165deg, #161922 0%, #0f1117 100%)",
          border: isAvailable
            ? "1px solid rgba(45, 212, 191, 0.45)"
            : "1px solid rgba(255, 255, 255, 0.12)",
          borderRadius: "18px",
          maxWidth: "500px",
          width: "100%",
          padding: "28px",
          boxShadow: "0 20px 50px rgba(0, 0, 0, 0.75)",
          color: "#f8fafc",
        }}
      >
        {/* Cabecera */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "18px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div
              style={{
                width: "44px",
                height: "44px",
                borderRadius: "12px",
                background: isAvailable
                  ? "rgba(45, 212, 191, 0.15)"
                  : "rgba(14, 165, 233, 0.12)",
                border: isAvailable
                  ? "1px solid rgba(45, 212, 191, 0.4)"
                  : "1px solid rgba(14, 165, 233, 0.3)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: isAvailable ? "#2dd4bf" : "#38bdf8",
              }}
            >
              {isAvailable ? <Rocket size={22} /> : <Shield size={22} />}
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: "1.15rem", fontWeight: 700 }}>
                {isAvailable ? "¡Nueva Versión Disponible!" : "Control de Versiones"}
              </h3>
              <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>
                {isAvailable
                  ? "Actualización obligatoria requerida para continuar"
                  : "Canal oficial de actualizaciones de Skop0"}
              </span>
            </div>
          </div>

          {canClose && (
            <button
              onClick={onClose}
              style={{
                background: "rgba(255, 255, 255, 0.06)",
                border: "1px solid rgba(255, 255, 255, 0.1)",
                color: "#94a3b8",
                width: "32px",
                height: "32px",
                borderRadius: "8px",
                cursor: "pointer",
                fontSize: "16px",
              }}
            >
              ✕
            </button>
          )}
        </div>

        {/* Comparativa de versiones */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            background: "rgba(255, 255, 255, 0.03)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "12px",
            padding: "14px 18px",
            marginBottom: "18px",
          }}
        >
          <div>
            <div style={{ fontSize: "0.72rem", color: "#64748b", textTransform: "uppercase", fontWeight: 600 }}>
              Versión Instalada
            </div>
            <div style={{ fontSize: "1.05rem", fontWeight: 700, color: "#cbd5e1", fontFamily: "monospace" }}>
              v{currentVer}
            </div>
          </div>

          <div style={{ color: "#64748b", fontSize: "1.2rem" }}>➔</div>

          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: "0.72rem", color: "#64748b", textTransform: "uppercase", fontWeight: 600 }}>
              Última en GitHub
            </div>
            <div
              style={{
                fontSize: "1.05rem",
                fontWeight: 700,
                color: isAvailable ? "#2dd4bf" : "#38bdf8",
                fontFamily: "monospace",
              }}
            >
              v{latestVer}
            </div>
          </div>
        </div>

        {/* Notas de la versión */}
        <div style={{ marginBottom: "20px" }}>
          <div style={{ fontSize: "0.78rem", color: "#94a3b8", fontWeight: 600, marginBottom: "8px" }}>
            {isAvailable ? `📋 Novedades en ${updateInfo?.release_title || `v${latestVer}`}:` : "Estado de tu instalación:"}
          </div>
          <div
            style={{
              background: "#0a0c10",
              border: "1px solid rgba(255, 255, 255, 0.08)",
              borderRadius: "10px",
              padding: "12px 14px",
              fontSize: "0.84rem",
              color: "#cbd5e1",
              lineHeight: 1.5,
              maxHeight: "150px",
              overflowY: "auto",
              whiteSpace: "pre-wrap",
            }}
          >
            {isAvailable ? (
              releaseNotes
            ) : (
              <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#10b981" }}>
                <CheckCircle size={16} />
                <span>Tu equipo cuenta con la última versión oficial compilada (v{currentVer}).</span>
              </div>
            )}
          </div>
        </div>

        {/* Barra de progreso si está descargando o instalando */}
        {(dlState === "downloading" || dlState === "installing") && (
          <div
            style={{
              marginBottom: "18px",
              padding: "14px",
              background: "rgba(14, 165, 233, 0.08)",
              border: "1px solid rgba(14, 165, 233, 0.3)",
              borderRadius: "10px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.82rem", marginBottom: "8px" }}>
              <span style={{ color: "#38bdf8", fontWeight: 600 }}>
                {dlState === "installing"
                  ? "⚙️ Ejecutando instalador y reiniciando Skop0..."
                  : `⬇️ Descargando actualización... (${dlMb} MB${totalMb ? ` / ${totalMb} MB` : ""})`}
              </span>
              <span style={{ color: "#f8fafc", fontWeight: 700 }}>{progress}%</span>
            </div>
            <div
              style={{
                width: "100%",
                height: "8px",
                background: "rgba(255, 255, 255, 0.08)",
                borderRadius: "99px",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${progress}%`,
                  height: "100%",
                  background: "linear-gradient(90deg, #0ea5e9, #2dd4bf)",
                  transition: "width 0.3s ease",
                }}
              />
            </div>
          </div>
        )}

        {/* Mensaje de error si falló la descarga */}
        {dlState === "error" && errorMsg && (
          <div
            style={{
              marginBottom: "16px",
              padding: "10px 14px",
              background: "rgba(239, 68, 68, 0.1)",
              border: "1px solid rgba(239, 68, 68, 0.35)",
              borderRadius: "8px",
              color: "#f87171",
              fontSize: "0.82rem",
              display: "flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            <AlertTriangle size={16} />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Botones de acción */}
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {isAvailable ? (
            <>
              <button
                onClick={handleStartAutoUpdate}
                disabled={dlState === "downloading" || dlState === "installing"}
                style={{
                  width: "100%",
                  padding: "13px 18px",
                  borderRadius: "10px",
                  border: "none",
                  background: "linear-gradient(135deg, #2dd4bf 0%, #0ea5e9 100%)",
                  color: "#06080f",
                  fontWeight: 700,
                  fontSize: "0.92rem",
                  cursor: dlState === "downloading" || dlState === "installing" ? "not-allowed" : "pointer",
                  opacity: dlState === "downloading" || dlState === "installing" ? 0.65 : 1,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "8px",
                  boxShadow: "0 4px 16px rgba(45, 212, 191, 0.25)",
                }}
              >
                <Rocket size={17} />
                {dlState === "downloading"
                  ? "Descargando instalador..."
                  : dlState === "installing"
                  ? "Instalando..."
                  : hasDirectExe
                  ? `Actualizar e Instalar Ahora (v${latestVer})`
                  : `Descargar Nueva Versión (v${latestVer})`}
              </button>

              <div style={{ display: "flex", gap: "10px" }}>
                <button
                  onClick={() => window.open(downloadUrl, "_blank")}
                  style={{
                    flex: 1,
                    padding: "10px 14px",
                    borderRadius: "8px",
                    border: "1px solid rgba(255, 255, 255, 0.12)",
                    background: "rgba(255, 255, 255, 0.04)",
                    color: "#cbd5e1",
                    fontSize: "0.82rem",
                    fontWeight: 600,
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "6px",
                  }}
                >
                  <ExternalLink size={14} /> Descargar por navegador
                </button>
              </div>
            </>
          ) : (
            <div style={{ display: "flex", gap: "10px" }}>
              <button
                onClick={onRefreshCheck}
                disabled={checkingUpdate}
                style={{
                  flex: 1,
                  padding: "11px 16px",
                  borderRadius: "10px",
                  border: "1px solid rgba(14, 165, 233, 0.35)",
                  background: "rgba(14, 165, 233, 0.12)",
                  color: "#38bdf8",
                  fontWeight: 600,
                  fontSize: "0.86rem",
                  cursor: checkingUpdate ? "not-allowed" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "8px",
                }}
              >
                <RefreshCw size={15} className={checkingUpdate ? "spin" : ""} />
                {checkingUpdate ? "Consultando GitHub..." : "Buscar actualizaciones ahora"}
              </button>

              <button
                onClick={onClose}
                style={{
                  padding: "11px 18px",
                  borderRadius: "10px",
                  border: "1px solid rgba(255, 255, 255, 0.1)",
                  background: "rgba(255, 255, 255, 0.05)",
                  color: "#cbd5e1",
                  fontSize: "0.86rem",
                  cursor: "pointer",
                }}
              >
                Cerrar
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
