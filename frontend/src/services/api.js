const API_BASE = (typeof window !== "undefined" && window.location.port !== "8000") 
  ? `http://${window.location.hostname || "localhost"}:8000` 
  : "";

const getHeaders = (token) => ({
  "Content-Type": "application/json",
  ...(token ? { "Authorization": `Bearer ${token}` } : {})
});

export async function triggerN8nScan(targetIp, token, scanId, passive = false, iface = "all") {
  const res = await fetch(`${API_BASE}/api/trigger-scan`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify({ 
      target_ip: targetIp,
      scan_id: scanId,
      passive,
      interface: iface || "all"
    }),
  });
  if (res.status === 503) {
    const err = new Error("SIN_INTERNET");
    err.code = "SIN_INTERNET";
    throw err;
  }
  if (res.status === 403) {
    const data = await res.json().catch(() => ({}));
    const err = new Error(data.detail || "Tu suscripción ha vencido.");
    err.code = "LICENCIA_EXPIRADA";
    throw err;
  }
  if (res.status === 409) {
    const data = await res.json().catch(() => ({}));
    const err = new Error(data.detail || "Ya existe una auditoría en curso.");
    err.code = "SCAN_ALREADY_RUNNING";
    throw err;
  }
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Error iniciando auditoría (HTTP ${res.status})`);
  }
  return res.json();
}

export async function cancelScan(scanId, token) {
  const targetId = scanId || "current";
  const res = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(targetId)}/cancel`, {
    method: "POST",
    headers: getHeaders(token),
  });
  return res.json();
}

export async function getDeviceTelemetry(ip, token) {
  const res = await fetch(`${API_BASE}/api/device-telemetry/${ip}`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function deepScan(ip, token) {
  const res = await fetch(`${API_BASE}/api/deep-scan/${ip}`, {
    method: "POST",
    headers: getHeaders(token),
  });
  if (res.status === 403) {
    const data = await res.json().catch(() => ({}));
    const err = new Error(data.detail || "Tu suscripción ha vencido.");
    err.code = "LICENCIA_EXPIRADA";
    throw err;
  }
  return res.json();
}

export async function getDevices(token) {
  const res = await fetch(`${API_BASE}/api/devices`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function getVulnerabilities(token) {
  const res = await fetch(`${API_BASE}/api/vulnerabilities`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function checkHealth(token) {
  const res = await fetch(`${API_BASE}/api/health`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function installNmap(token) {
  const res = await fetch(`${API_BASE}/api/install-nmap`, {
    method: "POST",
    headers: getHeaders(token),
  });
  return res.json();
}

export async function getScanHistory(token) {
  const res = await fetch(`${API_BASE}/api/history`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function getScanDetails(scanId, token) {
  const res = await fetch(`${API_BASE}/api/history/${scanId}`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function getScanDevices(scanId, token) {
  const res = await fetch(`${API_BASE}/api/history/${scanId}/devices`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function deleteScan(scanId, token) {
  const res = await fetch(`${API_BASE}/api/history/${scanId}`, {
    method: "DELETE",
    headers: getHeaders(token),
  });
  return res.json();
}

export async function deleteBatchScans(scanIds, token) {
  if (!scanIds || scanIds.length === 0) return { status: "ok", deleted_count: 0 };
  try {
    const res = await fetch(`${API_BASE}/api/history/batch-delete`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { "Authorization": `Bearer ${token}` } : {})
      },
      body: JSON.stringify({ scan_ids: scanIds })
    });
    return res.json();
  } catch (e) {
    return { status: "error", message: e.message };
  }
}

export async function getWifiNetworks(token) {
  const res = await fetch(`${API_BASE}/api/wifi/networks`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function connectWifi(ssid, password, token) {
  const res = await fetch(`${API_BASE}/api/wifi/connect`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify({ ssid, password }),
  });
  return res.json();
}

export async function getBackupList(token) {
  const res = await fetch(`${API_BASE}/api/backup/list`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function createBackup(name, token) {
  const res = await fetch(`${API_BASE}/api/backup/create`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify({ name }),
  });
  return res.json();
}

export async function restoreBackup(filename, token) {
  const res = await fetch(`${API_BASE}/api/backup/restore`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify({ filename }),
  });
  return res.json();
}

export async function deleteBackup(filename, token) {
  const res = await fetch(`${API_BASE}/api/backup/delete`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify({ filename }),
  });
  return res.json();
}

export async function sendShutdown() {
  const url = `${API_BASE}/api/shutdown`;
  try {
    if (typeof navigator !== "undefined" && navigator.sendBeacon) {
      navigator.sendBeacon(url);
      return;
    }
  } catch {}
  try {
    fetch(url, { method: "POST", keepalive: true }).catch(() => {});
  } catch {}
}

export async function getSubscriptionStatus(token) {
  const res = await fetch(`${API_BASE}/api/subscription/status`, {
    headers: getHeaders(token),
  });
  if (res.status === 403) {
    const data = await res.json().catch(() => ({}));
    const err = new Error(data.detail || "Licencia no activa");
    err.code = "LICENCIA_EXPIRADA";
    throw err;
  }
  return res.json();
}

export async function activateSubscriptionKey(key, token) {
  const res = await fetch(`${API_BASE}/api/subscription/activate`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify({ key }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "No se pudo activar la clave");
  }
  return data;
}

export async function refreshSubscription(token) {
  const res = await fetch(`${API_BASE}/api/subscription/refresh`, {
    method: "POST",
    headers: getHeaders(token),
  });
  if (!res.ok) {
    throw new Error("No se pudo refrescar el estado de la suscripción");
  }
  return res.json();
}

export async function getNetworkInterfaces(token) {
  try {
    const res = await fetch(`${API_BASE}/api/interfaces`, {
      headers: getHeaders(token),
    });
    return res.json();
  } catch (e) {
    return { status: "error", interfaces: [] };
  }
}

export async function getSubnetBridgeStatus(target, token, iface = null) {
  let url = `${API_BASE}/api/bridge-status?target=${encodeURIComponent(target || "")}`;
  if (iface && iface !== "all") {
    url += `&interface=${encodeURIComponent(iface)}`;
  }
  const res = await fetch(url, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function bindSubnetBridge(target, token, iface = null) {
  const res = await fetch(`${API_BASE}/api/bridge-bind`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify({ target, interface: iface }),
  });
  return res.json();
}

export async function unbindSubnetBridge(token) {
  const res = await fetch(`${API_BASE}/api/bridge-unbind`, {
    method: "POST",
    headers: getHeaders(token),
  });
  return res.json();
}


export async function exportBackup(token) {
  const res = await fetch(`${API_BASE}/api/backup/export`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function importBackup(payload, token) {
  const res = await fetch(`${API_BASE}/api/backup/import`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify(payload),
  });
  return res.json();
}


export async function sendHeartbeat() {
  try {
    if (typeof navigator !== "undefined" && navigator.sendBeacon) {
      navigator.sendBeacon(`${API_BASE}/api/heartbeat`);
    } else {
      fetch(`${API_BASE}/api/heartbeat`, { method: "POST" }).catch(() => {});
    }
  } catch (e) {}
}

export const refreshSubscriptionStatus = refreshSubscription;


export async function checkAppUpdate(token) {
  try {
    const res = await fetch(`${API_BASE}/api/check-update`, {
      headers: getHeaders(token),
    });
    return res.json();
  } catch (e) {
    return { status: "error", update_available: false };
  }
}

export async function startUpdateDownload(payload, token) {
  const res = await fetch(`${API_BASE}/api/download-update`, {
    method: "POST",
    headers: getHeaders(token),
    body: JSON.stringify(payload || {}),
  });
  return res.json();
}

export async function getUpdateProgress(token) {
  const res = await fetch(`${API_BASE}/api/update-progress`, {
    headers: getHeaders(token),
  });
  return res.json();
}

export async function applyAppUpdate(token) {
  const res = await fetch(`${API_BASE}/api/apply-update`, {
    method: "POST",
    headers: getHeaders(token),
  });
  return res.json();
}
