/**
 * Delegation Revocation — Post-rescue cleanup.
 *
 * VERIFIED: Delegating to address(0) clears the EIP-7702
 * delegation, returning the EOA to its pure state.
 *
 * This MUST be called after every rescue to prevent the BatchExecutor
 * delegation from remaining active (which would let anyone call
 * executeRescue on the EOA).
 */

export { signRevocationAuthorization } from "./authorization.js";
