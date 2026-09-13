# Signer revision history review

The dedicated signer repository was created through Lovable's existing GitHub connection in the owner's account and synchronized on `main`. It is private pending deployment review. Published history is preserved; no force push, squash or history rewrite was performed.

At source `079d1b67affbc3bc0844dac653e5c696d76be6e4`, checksum-verified Gitleaks 8.30.1 scanned all 28 fetched commits (436,443 bytes). Two initial-template `.env` entries were flagged. Variable-name and prefix inspection confirmed these are `SUPABASE_PUBLISHABLE_KEY` and `VITE_SUPABASE_PUBLISHABLE_KEY`, both `sb_publishable_` public-client identifiers, not elevated server or wallet credentials. Values were not displayed. Supabase's [API-key documentation](https://supabase.com/docs/guides/getting-started/api-keys) describes this credential class as suitable for public clients; database grants/RLS still control access.

Only those two historical finding fingerprints are reviewed in `.gitleaksignore`. No broad file/path/rule exemption is introduced. Wallet seeds, encryption keys, caller secrets and elevated backend credentials must never enter commits, chat or logs.

Re-run with `gitleaks git . --log-opts=--all --redact=100 --no-banner --ignore-gitleaks-allow --timeout=120`. Later source commits and runtime activation require fresh review; this record is not a deployed-service security certification.
