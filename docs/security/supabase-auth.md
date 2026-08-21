# Supabase Auth: leaked-password protection

**Adviser finding:** leaked-password protection is disabled.

**Assessment: not currently applicable to the exposed auth model, so no behaviour
is changed here.**

The application's sign-in flow is passwordless. `frontend/src/lib/auth.jsx` uses
only:

- `signInWithOtp` (email magic link), and
- `signInWithOAuth` (Google / GitHub / Azure).

There is no email+password sign-up or sign-in surface in the product. Supabase's
leaked-password protection (HaveIBeenPwned check) applies to the **password**
credential flow, which this app does not use, so enabling it would have no effect
on the current users.

## Owner action, only if password auth is ever enabled

Leaked-password protection is a dashboard setting and cannot be version-controlled.
If a password sign-in flow is added later, the owner should enable it:

> Supabase Dashboard -> Authentication -> Policies (Password) -> enable
> "Leaked password protection" (rejects passwords found in known breach corpora).

Until a password flow exists, this finding is documented and intentionally left as
is rather than toggling an unrelated setting.

## Related (out of scope but noted)

The magic-link redirect Site URL must be set to the production origin in the
dashboard (Authentication -> URL Configuration). This is tracked separately from
this security work package and is a dashboard-only setting.
