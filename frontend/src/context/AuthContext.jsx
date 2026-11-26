import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { onAuthStateChanged, signInWithPopup, signInWithRedirect, getRedirectResult, signOut } from "firebase/auth";
import { auth, googleProvider } from "../firebase";
import { getSubscriptionStatus } from "../services/api";

const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [subscription, setSubscription] = useState(null);
  const [loading, setLoading] = useState(true);

  // 0. Capturar resultado de redirección directa si se usó signInWithRedirect
  useEffect(() => {
    getRedirectResult(auth)
      .then((res) => {
        if (res && res.user) {
          setUser(res.user);
          setLoading(false);
        }
      })
      .catch((err) => {
        console.warn("getRedirectResult warn:", err);
      });
  }, []);

  // 1. Manejo de autenticación Firebase
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setLoading(false);
      if (!currentUser) {
        setSubscription(null);
      }
    });
    return () => unsubscribe();
  }, []);

  // 2. Monitoreo en tiempo real: cada 2 segundos consulta el backend
  useEffect(() => {
    if (!user) return;

    let isMounted = true;

    const check = async () => {
      try {
        const token = await user.getIdToken();
        if (!token) return;
        const data = await getSubscriptionStatus(token);
        if (isMounted && data) {
          setSubscription(data);
        }
      } catch (err) {
        // Ignorar errores transitorios de red
      }
    };

    // Consulta inicial inmediata al cargar
    check();

    // Consulta periódica cada 2 segundos
    const timer = setInterval(check, 2000);

    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, [user]);

  const refreshSubscription = useCallback(async () => {
    if (!user) return null;
    try {
      const token = await user.getIdToken();
      if (!token) return null;
      const data = await getSubscriptionStatus(token);
      if (data) {
        setSubscription(data);
      }
      return data;
    } catch (_) {
      return null;
    }
  }, [user]);

  const loginWithGoogle = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (error) {
      console.warn("Error en popup de Google:", error?.code, error?.message);
      if (error?.code === "auth/popup-blocked" || error?.code === "auth/cancelled-popup-request") {
        console.log("Reintentando inicio de sesión con redirección directa...");
        await signInWithRedirect(auth, googleProvider);
        return;
      }
      throw error;
    }
  };

  const logout = () => {
    setSubscription(null);
    return signOut(auth);
  };

  const getToken = useCallback(async () => {
    if (!auth.currentUser) return null;
    return await auth.currentUser.getIdToken();
  }, []);

  return (
    <AuthContext.Provider value={{ 
      user, 
      subscription, 
      setSubscription, 
      refreshSubscription, 
      loginWithGoogle, 
      logout, 
      getToken, 
      loading 
    }}>
      {loading ? (
        <div
          style={{
            minHeight: "100vh",
            background: "radial-gradient(circle at 50% 30%, #172554 0%, #0a0f1d 70%, #030712 100%)",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            color: "#f8fafc",
            fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
          }}
        >
          <img
            src="/favicon.svg?v=skop0"
            alt="Skop0"
            style={{
              width: "76px",
              height: "76px",
              marginBottom: "18px",
              filter: "drop-shadow(0 0 18px rgba(34, 211, 238, 0.4))",
            }}
          />
          <div style={{ fontSize: "24px", fontWeight: 800, letterSpacing: "-0.4px", marginBottom: "8px" }}>
            Skop<span style={{ color: "#22d3ee" }}>0</span>
          </div>
          <div style={{ fontSize: "12.5px", color: "#94a3b8" }}>
            Validando sesión...
          </div>
        </div>
      ) : (
        children
      )}
    </AuthContext.Provider>
  );
};
