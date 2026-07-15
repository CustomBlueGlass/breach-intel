import { createClient } from '@supabase/supabase-js';

const url = import.meta.env.VITE_SUPABASE_URL;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!url || !anonKey) {
  // Fails loudly at build/runtime rather than silently showing a blank page —
  // means the Vercel project is missing its environment variables.
  console.error(
    'Missing VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY. Set these in ' +
    'Vercel → Project → Settings → Environment Variables.'
  );
}

// This is the public "anon" key — safe to expose in frontend code. It can
// only ever SELECT, per the read-only RLS policies in db/supabase_grants.sql.
// Never put a service-role key in frontend code.
export const supabase = createClient(url, anonKey);
