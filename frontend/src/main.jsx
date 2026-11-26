// Redirigir siempre a localhost si se abrió con 127.0.0.1 para que Firebase Auth reconozca el dominio autorizado
if (typeof window !== 'undefined' && window.location.hostname === '127.0.0.1') {
  const newUrl = window.location.href.replace('127.0.0.1', 'localhost');
  window.location.replace(newUrl);
}

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
