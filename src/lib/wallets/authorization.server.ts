/**
 * Server-owned provisioning authorization (SOURCE ONLY).
 *
 * Group and membership are NEVER derived from Telegram initData and NEVER taken
 * from a client-selected group: initData proves only a Telegram user id.
 * Provisioning therefore requires an explicit server-owned authorization
 * callback that answers, from the trusted BRUH member/group system, whether this
 * verified Telegram user is an approved member of the named chat, and which
 * group/membership UUIDs that maps to.
 *
 * A missing callback, a thrown callback, an unapproved answer, or an answer that
 * does not match the request's claim rejects the request. There is no fallback
 * and no default-allow.
 */

export type MembershipApprovalRequest = {
  /** From the verified initData signature only. */
  telegramUserId: string;
  /** Claimed chat id; the callback must confirm or deny it. */
  telegramChatId: string;
};

export type MembershipApproval = {
  approved: true;
  /** Authoritative UUIDs decided by the trusted BRUH system. */
  groupId: string;
  membershipId: string;
  telegramChatId: string;
  telegramUserId: string;
};

export type MembershipDenial = { approved: false };

/**
 * Trusted server-side callback. MUST reach the BRUH member/group system; MUST
 * NOT consult request-supplied group data. Throw on any upstream failure so the
 * caller fails closed.
 */
export type MembershipAuthorizer = (
  input: MembershipApprovalRequest,
) => Promise<MembershipApproval | MembershipDenial>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TELEGRAM_ID = /^[0-9]{1,20}$/;
const TELEGRAM_CHAT_ID = /^-?[0-9]{1,20}$/;

/**
 * Validates an approval and re-binds it to the verified request facts. Any
 * mismatch or malformed field is a denial, not a warning.
 */
export function validateApproval(
  request: MembershipApprovalRequest,
  approval: MembershipApproval | MembershipDenial | null | undefined,
): MembershipApproval | null {
  if (!approval || approval.approved !== true) return null;
  if (
    !UUID.test(approval.groupId) ||
    !UUID.test(approval.membershipId) ||
    !TELEGRAM_ID.test(approval.telegramUserId) ||
    !TELEGRAM_CHAT_ID.test(approval.telegramChatId) ||
    approval.telegramUserId !== request.telegramUserId ||
    approval.telegramChatId !== request.telegramChatId
  ) {
    return null;
  }
  return {
    approved: true,
    groupId: approval.groupId,
    membershipId: approval.membershipId,
    telegramChatId: approval.telegramChatId,
    telegramUserId: approval.telegramUserId,
  };
}

/**
 * Production authorizer is NOT configured: no trusted BRUH membership endpoint,
 * credential or contract is wired into this project yet. Returning null makes
 * provisioning reject with `authorization_unavailable` (fail closed). Mock
 * authorizers used by tests live in scripts/support/ and are clearly labelled
 * fixtures, not real membership proof.
 */
export async function getProductionMembershipAuthorizer(): Promise<MembershipAuthorizer | null> {
  return null;
}
