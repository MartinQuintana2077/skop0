import os
import subprocess
import sys
import time

def install_nmap_silently():
    """
    Descarga el instalador oficial de Nmap para Windows y lo ejecuta de forma asistida o desatendida.
    """
    nmap_url = "https://nmap.org/dist/nmap-7.95-setup.exe"
    installer_path = os.path.join(os.environ.get("TEMP", "C:\\temp"), "nmap_setup_secscan_temp.exe")
    
    try:
        print(f"Iniciando descarga de motor Nmap (32MB aprox)...")
        
        import requests
        response = requests.get(nmap_url, stream=True, timeout=60)
        response.raise_for_status()
        
        with open(installer_path, 'wb') as f:
            for data in response.iter_content(1024 * 1024):
                f.write(data)

        print(f"Descarga finalizada en: {installer_path}")
        print("Iniciando instalador oficial de Nmap con elevación...")
        
        if sys.platform == 'win32':
            import ctypes
            # ShellExecuteW nativo de Windows para solicitar UAC limpiamente sin PowerShell
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", installer_path, "", None, 1)
            if ret > 32:
                print("¡Asistente de Nmap lanzado exitosamente!")
                return True
            else:
                # Intentar modo normal
                ctypes.windll.shell32.ShellExecuteW(None, "open", installer_path, "", None, 1)
                return True
        return True
    except Exception as e:
        print(f"Error grave auto-instalando Nmap: {e}")
        return False
