import React from "react";
import { Check, Layers } from "lucide-react";

export const SECSCAN_THEMES = [
  {
    id: "original",
    name: "Cyan & Sky",
    tag: "Original",
    swatches: ["#0a0a0c", "#18181b", "#2dd4bf", "#38bdf8"],
  },
  {
    id: "emerald",
    name: "Cyber Emerald",
    tag: "SOC",
    swatches: ["#060a09", "#101a17", "#10b981", "#34d399"],
  },
  {
    id: "amber",
    name: "Obsidian & Amber",
    tag: "Industrial / CCTV",
    swatches: ["#0b0c10", "#171a22", "#f59e0b", "#fb923c"],
  },
  {
    id: "indigo",
    name: "Midnight Indigo",
    tag: "Corporativo",
    swatches: ["#070914", "#12172f", "#6366f1", "#38bdf8"],
  },
  {
    id: "crimson",
    name: "Crimson Sentinel",
    tag: "Red Team",
    swatches: ["#09070a", "#191217", "#f43f5e", "#fb7185"],
  },
];

export const SECSCAN_LAYOUTS = [
  {
    id: "original",
    name: "Bento Original",
    desc: "Distribución clásica en tarjetas independientes + historial abajo.",
  },
  {
    id: "command",
    name: "Command Center",
    desc: "Centro de comando unificado arriba con pestañas (Auto / Objetivo) y consola amplia debajo.",
  },
  {
    id: "minimal",
    name: "Minimalist Focus",
    desc: "Barra central estilo buscador para escanear al instante + 3 módulos compactos debajo.",
  },
];

export function applySavedAppearance() {
  try {
    const savedTheme = localStorage.getItem("secscan_theme") || "original";
    if (savedTheme === "original") {
      document.documentElement.removeAttribute("data-theme");
    } else {
      document.documentElement.setAttribute("data-theme", savedTheme);
    }
  } catch (e) {}
}

export default function AppearanceModal({
  isOpen,
  onClose,
  currentTheme,
  onSelectTheme,
  currentLayout,
  onSelectLayout,
  isFirstRun = false,
}) {
  if (!isOpen) return null;

  return (
    <div
      className="modal-overlay"
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(6, 8, 15, 0.82)",
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
          background: "var(--bg-card)",
          border: "1px solid var(--border-base)",
          borderRadius: "18px",
          maxWidth: "560px",
          width: "100%",
          padding: "26px",
          boxShadow: "0 20px 50px rgba(0, 0, 0, 0.75)",
          color: "var(--text-primary)",
          maxHeight: "90vh",
          overflowY: "auto",
        }}
      >
        {/* Cabecera */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div
              style={{
                width: "40px",
                height: "40px",
                borderRadius: "11px",
                background: "var(--cyan-dim)",
                border: "1px solid var(--cyan-border)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "20px",
              }}
            >
              🎨
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 700 }}>
                {isFirstRun ? "Personaliza tu Skop0" : "Apariencia y Diseño"}
              </h3>
              {isFirstRun && (
                <span style={{ fontSize: "0.76rem", color: "var(--text-secondary)" }}>
                  Elige tu paleta de colores y modo de vista preferido para empezar
                </span>
              )}
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: "rgba(255, 255, 255, 0.06)",
              border: "1px solid var(--border-base)",
              color: "var(--text-secondary)",
              width: "32px",
              height: "32px",
              borderRadius: "8px",
              cursor: "pointer",
              fontSize: "15px",
            }}
          >
            ✕
          </button>
        </div>

        {/* Sección 1: Paletas de Colores */}
        <div style={{ marginBottom: "22px" }}>
          <div
            style={{
              fontSize: "0.74rem",
              fontWeight: 700,
              color: "var(--text-muted)",
              textTransform: "uppercase",
              letterSpacing: "0.6px",
              marginBottom: "10px",
            }}
          >
            1. Paleta de Colores
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: "10px" }}>
            {SECSCAN_THEMES.map((t) => {
              const active = currentTheme === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => onSelectTheme(t.id)}
                  style={{
                    textAlign: "left",
                    padding: "12px",
                    borderRadius: "12px",
                    background: active ? "var(--cyan-dim)" : "var(--bg-surface)",
                    border: active ? "1px solid var(--cyan-400)" : "1px solid var(--border-base)",
                    cursor: "pointer",
                    color: "var(--text-primary)",
                    transition: "all 0.2s ease",
                    position: "relative",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                    <span style={{ fontSize: "0.82rem", fontWeight: 700 }}>{t.name}</span>
                    {active && <Check size={14} color="var(--cyan-400)" />}
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    {t.swatches.map((hex, i) => (
                      <span
                        key={i}
                        style={{
                          width: "15px",
                          height: "15px",
                          borderRadius: "50%",
                          background: hex,
                          border: "1px solid rgba(255,255,255,0.22)",
                          display: "inline-block",
                        }}
                      />
                    ))}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Sección 2: Vista previa en vivo de disposiciones */}
        <div style={{ marginBottom: "18px" }}>
          <div
            style={{
              fontSize: "0.74rem",
              fontWeight: 700,
              color: "var(--text-muted)",
              textTransform: "uppercase",
              letterSpacing: "0.6px",
              marginBottom: "10px",
              display: "flex",
              alignItems: "center",
              gap: "6px",
            }}
          >
            <Layers size={13} /> 2. Disposición de Pantalla
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {SECSCAN_LAYOUTS.map((l) => {
              const active = currentLayout === l.id;
              return (
                <button
                  key={l.id}
                  type="button"
                  onClick={() => onSelectLayout(l.id)}
                  style={{
                    textAlign: "left",
                    padding: "13px 16px",
                    borderRadius: "12px",
                    background: active ? "var(--purple-dim)" : "var(--bg-surface)",
                    border: active ? "1px solid var(--purple-400)" : "1px solid var(--border-base)",
                    cursor: "pointer",
                    color: "var(--text-primary)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "12px",
                    transition: "all 0.2s ease",
                  }}
                >
                  <div style={{ fontSize: "0.9rem", fontWeight: 700 }}>
                    {l.name}
                  </div>
                  {active && (
                    <span
                      style={{
                        background: "var(--purple-400)",
                        color: "#06080f",
                        fontSize: "0.68rem",
                        fontWeight: 800,
                        padding: "3px 8px",
                        borderRadius: "99px",
                        flexShrink: 0,
                      }}
                    >
                      ACTIVO
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        <button
          onClick={onClose}
          className="bento-btn bento-btn-primary"
          style={{ width: "100%", padding: "11px" }}
        >
          {isFirstRun ? "Continuar →" : "Aplicar y Cerrar"}
        </button>

        {isFirstRun && (
          <div style={{ marginTop: "10px", textAlign: "center", fontSize: "0.72rem", color: "var(--text-muted)" }}>
            Podrás volver a cambiar esto en cualquier momento desde el menú lateral (☰).
          </div>
        )}
      </div>
    </div>
  );
}
