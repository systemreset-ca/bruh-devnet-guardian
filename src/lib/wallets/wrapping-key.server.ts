/**
 * Production wrapping-key injection contract (SOURCE ONLY).
 *
 * The custody vault requires an explicitly injected, non-extractable AES-256-GCM
 * CryptoKey. This module deliberately provides NO production key: there is no
 * demo key, no env-derived key, no generated-on-boot key and no fallback. A
 * production key-management path (injection of a non-extractable key material
 * handle plus a key version) is NOT configured in this project, so provisioning
 * fails closed with `wrapping_key_unavailable`.
 */
import { DevnetCustodyVault } from "@/lib/custody/custody-vault.server";

export type WrappingKeyInjection = {
  /** Non-extractable AES-256-GCM key; validated by DevnetCustodyVault. */
  key: CryptoKey;
  keyVersion: string;
};

export function vaultFromInjection(injection: WrappingKeyInjection): DevnetCustodyVault {
  // The constructor rejects extractable keys, wrong algorithms and wrong sizes.
  return new DevnetCustodyVault(injection.key, injection.keyVersion);
}

/** Always null in this slice: no production wrapping key exists. */
export async function getProductionWrappingVault(): Promise<DevnetCustodyVault | null> {
  return null;
}
