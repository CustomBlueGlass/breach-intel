import React, { createContext, useContext, useEffect, useState } from 'react';
import { supabase } from './supabaseClient';

/* Auth context backed by Supabase Auth (the same client we already use for
   reads). Passwordless magic-link is the primary flow; OAuth works once the
   provider is enabled in the Supabase dashboard. No card data or billing here:
   this is P1 (login + dashboard), tier defaults to Free until billing lands. */

const AuthCtx = createContext({
  session: null,
  user: null,
  loading: true,
  signInWithEmail: async () => {},
  signInWithOAuth: async () => {},
  signOut: async () => {},
});

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    supabase.auth
      .getSession()
      .then(({ data }) => {
        if (active) {
          setSession(data?.session || null);
          setLoading(false);
        }
      })
      .catch(() => active && setLoading(false));
    const { data: listener } = supabase.auth.onAuthStateChange((_event, s) => setSession(s));
    return () => {
      active = false;
      listener?.subscription?.unsubscribe?.();
    };
  }, []);

  const value = {
    session,
    user: session?.user || null,
    loading,
    signInWithEmail: (email) =>
      supabase.auth.signInWithOtp({
        email,
        options: { emailRedirectTo: window.location.origin },
      }),
    signInWithOAuth: (provider) =>
      supabase.auth.signInWithOAuth({
        provider,
        options: { redirectTo: window.location.origin },
      }),
    signOut: () => supabase.auth.signOut(),
  };

  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export const useAuth = () => useContext(AuthCtx);
