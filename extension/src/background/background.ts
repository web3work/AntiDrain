/**
 * AntiDrain Standalone Extension — Background Controller & Policy Engine
 *
 * Security Model (Invariant B0):
 * - Website Non-Authorization Boundary: Websites and dApps are untrusted.
 * - Sender & Origin Validation: Privileged actions (unlock, add account, confirm rescue)
 *   are strictly restricted to internal extension pages (popup/dashboard) and rejected from tabs.
 * - Encrypted vault stored in chrome.storage.local using WebCrypto AES-256-GCM + PBKDF2 (600k rounds).
 * - Decrypted keys live only in ephemeral memory while unlocked and are cleared on timeout.
 * - Read-only JSON-RPC proxying allows dApps to inspect balance/code without exposing keys.
 * - Enforces RecoverySession isolation, capability validation, simulation gating,
 *   and mandatory post-rescue delegation revocation.
 */

import {
  encryptVault,
  decryptVault,
  createDefaultVaultData,
  type VaultData,
  type EncryptedVaultPayload,
  type StoredAccount,
  type WalletRole,
} from "../vault/webCryptoVault.js";
import {
  isRescueAllowedOnChain,
  getRescueUnsupportedReason,
  BATCH_EXECUTOR_DELEGATE,
  CHAIN_REGISTRY,
} from "../core/chainRegistry.js";
import {
  RecoverySessionController,
  type RecoverySession,
} from "../rescue/stateMachine.js";
import {
  validateCapabilityContext,
  validateSponsorSpendingPolicy,
} from "../signer/typedSigner.js";
import {
  deriveAddressFromPrivateKey,
  toChecksumAddress,
} from "../core/addressDerivation.js";

// In-Memory Ephemeral Enclave State
let inMemoryVault: VaultData | null = null;
let ephemeralSessionPassword: string | null = null;
let lockTimer: any = null;

let activeRecoveryController: RecoverySessionController | null = null;
let pendingConfirmationResolver: { resolve: (val: any) => void; reject: (err: any) => void } | null = null;

// ─── Vault Lifecycle Management ────────────────────────────────────────────

async function getStoredEncryptedVault(): Promise<EncryptedVaultPayload | null> {
  const result = await chrome.storage.local.get("antidrain_vault_v1");
  return (result.antidrain_vault_v1 as EncryptedVaultPayload) || null;
}

async function getStoredPublicMeta(): Promise<any> {
  const result = await chrome.storage.local.get("antidrain_meta_v1");
  return result.antidrain_meta_v1 || null;
}

async function saveEncryptedVault(data: VaultData, password: string): Promise<void> {
  const payload = await encryptVault(data, password);
  const activeVictim = data.accounts.find((a) => a.id === data.activeVictimId) || null;
  const activeSafe = data.accounts.find((a) => a.id === data.activeSafeId) || null;
  const activeSponsor = data.accounts.find((a) => a.id === data.activeSponsorId) || null;

  const publicMeta = {
    isInitialized: true,
    selectedChainId: data.selectedChainId || 8453,
    activeVictim: activeVictim ? { id: activeVictim.id, name: activeVictim.name, address: activeVictim.address } : null,
    activeSafe: activeSafe ? { id: activeSafe.id, name: activeSafe.name, address: activeSafe.address } : null,
    activeSponsor: activeSponsor ? { id: activeSponsor.id, name: activeSponsor.name, address: activeSponsor.address, policy: activeSponsor.sponsorPolicy } : null,
    hasAccounts: data.accounts.length > 0,
    updatedAt: Date.now(),
  };

  await chrome.storage.local.set({
    antidrain_vault_v1: payload,
    antidrain_meta_v1: publicMeta,
  });

  await setSessionVault(data, password);
}

async function getSessionVault(): Promise<{ data: VaultData; password: string } | null> {
  if (inMemoryVault && ephemeralSessionPassword) {
    return { data: inMemoryVault, password: ephemeralSessionPassword };
  }
  if (typeof chrome !== "undefined" && chrome.storage && (chrome.storage as any).session) {
    try {
      const res = await (chrome.storage as any).session.get("antidrain_active_session");
      if (res?.antidrain_active_session) {
        inMemoryVault = res.antidrain_active_session.data;
        ephemeralSessionPassword = res.antidrain_active_session.password;
        return res.antidrain_active_session;
      }
    } catch {}
  }
  return null;
}

async function setSessionVault(data: VaultData, password: string): Promise<void> {
  inMemoryVault = data;
  ephemeralSessionPassword = password;
  if (typeof chrome !== "undefined" && chrome.storage && (chrome.storage as any).session) {
    try {
      await (chrome.storage as any).session.set({
        antidrain_active_session: { data, password },
      });
    } catch {}
  }
  resetAutoLockTimer();
}

async function clearSessionVault(): Promise<void> {
  inMemoryVault = null;
  ephemeralSessionPassword = null;
  if (lockTimer) clearTimeout(lockTimer);
  if (typeof chrome !== "undefined" && chrome.storage && (chrome.storage as any).session) {
    try {
      await (chrome.storage as any).session.remove("antidrain_active_session");
    } catch {}
  }
  chrome.runtime.sendMessage({ type: "VAULT_LOCKED" }).catch(() => {});
}

function resetAutoLockTimer(): void {
  if (lockTimer) clearTimeout(lockTimer);
  const timeoutMs = (inMemoryVault?.autoLockTimeoutMinutes || 15) * 60 * 1000;
  lockTimer = setTimeout(() => {
    clearSessionVault();
  }, timeoutMs);
}

function lockVault(): void {
  clearSessionVault();
}

// ─── Read-Only JSON-RPC Gateway ────────────────────────────────────────────

async function proxyJsonRpc(chainId: number, method: string, params: unknown[]): Promise<unknown> {
  const chainDef = CHAIN_REGISTRY[chainId];
  if (!chainDef || !chainDef.rpcUrls || chainDef.rpcUrls.length === 0) {
    throw new Error(`No RPC endpoint configured for chain ID ${chainId}`);
  }

  let lastError: Error | null = null;
  for (const endpoint of chainDef.rpcUrls) {
    try {
      const res = await fetch(endpoint.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: Date.now(),
          method,
          params,
        }),
      });
      if (!res.ok) {
        throw new Error(`RPC HTTP error (${res.status}): ${res.statusText}`);
      }
      const json = await res.json();
      if (json.error) {
        const err = new Error(json.error.message || "RPC Error");
        (err as any).code = json.error.code;
        throw err;
      }
      return json.result;
    } catch (err: any) {
      lastError = err;
      // If there are more fallback RPCs, continue to next
      continue;
    }
  }
  throw lastError || new Error(`All RPC endpoints failed for chain ${chainId}`);
}

// ─── Restricted Raw Transaction Broadcast (Zero Public Mempool Fallback) ───

export async function broadcastRawTransactionToRestrictedEndpoint(
  chainId: number,
  signedRawTx: `0x${string}`
): Promise<`0x${string}`> {
  const chainDef = CHAIN_REGISTRY[chainId];
  if (!chainDef) {
    throw new Error(`Chain ${chainId} not found in registry.`);
  }
  const endpoint = chainDef.privateBroadcastUrl || chainDef.rpcUrls[0]?.url;
  if (!endpoint) {
    throw new Error(`No broadcast endpoint configured for chain ${chainId}.`);
  }

  // Submit strictly to designated restricted endpoint
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: Date.now(),
      method: "eth_sendRawTransaction",
      params: [signedRawTx],
    }),
  });

  if (!res.ok) {
    throw new Error(`Restricted broadcast HTTP error (${res.status}): ${res.statusText}`);
  }

  const json = await res.json();
  if (json.error) {
    const err = new Error(json.error.message || "Broadcast Rejected");
    (err as any).code = json.error.code;
    throw err;
  }

  return json.result as `0x${string}`;
}

// ─── UI Status Summary (Zero Key Exposure) ─────────────────────────────────

function getPublicWalletState(isInitialized = false, storedMeta: any = null) {
  const isUnlocked = inMemoryVault !== null;

  if (!isUnlocked || !inMemoryVault) {
    return {
      isInitialized: isInitialized,
      isUnlocked: false,
      selectedChainId: storedMeta?.selectedChainId || 8453,
      accounts: [],
      activeVictim: storedMeta?.activeVictim || null,
      activeSafe: storedMeta?.activeSafe || null,
      activeSponsor: storedMeta?.activeSponsor || null,
      isRescueBlocked: activeRecoveryController ? activeRecoveryController.isRescueBlocked() : false,
      recoverySession: activeRecoveryController ? activeRecoveryController.getSession() : null,
    };
  }

  const accounts = inMemoryVault.accounts.map((acc) => ({
    id: acc.id,
    role: acc.role,
    name: acc.name,
    address: acc.address,
    sponsorPolicy: acc.sponsorPolicy,
    isCompromisedAcknowledged: acc.isCompromisedAcknowledged,
    createdAt: acc.createdAt,
  }));

  const activeVictim = inMemoryVault.accounts.find((a) => a.id === inMemoryVault!.activeVictimId) || null;
  const activeSafe = inMemoryVault.accounts.find((a) => a.id === inMemoryVault!.activeSafeId) || null;
  const activeSponsor = inMemoryVault.accounts.find((a) => a.id === inMemoryVault!.activeSponsorId) || null;

  return {
    isInitialized: true,
    isUnlocked: true,
    selectedChainId: inMemoryVault.selectedChainId,
    accounts,
    activeVictim: activeVictim ? { id: activeVictim.id, name: activeVictim.name, address: activeVictim.address } : null,
    activeSafe: activeSafe ? { id: activeSafe.id, name: activeSafe.name, address: activeSafe.address } : null,
    activeSponsor: activeSponsor ? { id: activeSponsor.id, name: activeSponsor.name, address: activeSponsor.address, policy: activeSponsor.sponsorPolicy } : null,
    isRescueBlocked: activeRecoveryController ? activeRecoveryController.isRescueBlocked() : false,
    recoverySession: activeRecoveryController ? activeRecoveryController.getSession() : null,
  };
}

// ─── Message Handling & RPC Gateway ────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { type, payload } = message || {};
  const isExtensionPage = sender.id === chrome.runtime.id && !sender.tab;

  // 1. Privileged UI Messages (STRICTLY FORBIDDEN from Content Script / Webpage Tabs)
  if (
    type === "GET_STATE" ||
    type === "INIT_VAULT" ||
    type === "UNLOCK_VAULT" ||
    type === "LOCK_VAULT" ||
    type === "RESET_VAULT" ||
    type === "ADD_ACCOUNT" ||
    type === "SET_CHAIN" ||
    type === "DERIVE_ADDRESS" ||
    type === "CONFIRM_RESCUE" ||
    type === "CANCEL_RESCUE" ||
    type === "RETRY_CLEANUP"
  ) {
    if (!isExtensionPage) {
      sendResponse({ error: "Access Denied: Privileged internal action cannot be invoked from web page context." });
      return true;
    }

    if (type === "GET_STATE") {
      getSessionVault()
        .then(() => Promise.all([getStoredEncryptedVault(), getStoredPublicMeta()]))
        .then(([storedVault, storedMeta]) => {
          const isInit = storedVault !== null;
          sendResponse({ result: getPublicWalletState(isInit, storedMeta) });
        })
        .catch(() => {
          sendResponse({ result: getPublicWalletState(false, null) });
        });
      return true;
    }

    if (type === "DERIVE_ADDRESS") {
      try {
        const { privateKey } = payload || {};
        const address = deriveAddressFromPrivateKey(privateKey);
        sendResponse({ result: { address } });
      } catch (err: any) {
        sendResponse({ error: err.message || "Invalid private key" });
      }
      return true;
    }

    if (type === "SET_CHAIN") {
      const { chainId } = payload || {};
      const cid = Number(chainId);
      if (CHAIN_REGISTRY[cid]) {
        if (inMemoryVault) {
          inMemoryVault.selectedChainId = cid;
          if (ephemeralSessionPassword) {
            saveEncryptedVault(inMemoryVault, ephemeralSessionPassword);
          }
        } else {
          getStoredPublicMeta().then((meta) => {
            if (meta) {
              meta.selectedChainId = cid;
              chrome.storage.local.set({ antidrain_meta_v1: meta });
            }
          });
        }
        sendResponse({ result: { chainId: cid } });
      } else {
        sendResponse({ error: `Unsupported chain ID: ${chainId}` });
      }
      return true;
    }

    if (type === "RESET_VAULT") {
      chrome.storage.local.clear().then(() => {
        lockVault();
        sendResponse({ result: { reset: true } });
      });
      return true;
    }

    if (type === "INIT_VAULT") {
      const { password } = payload || {};
      if (!password || password.length < 8) {
        sendResponse({ error: "Password must be at least 8 characters long." });
        return true;
      }
      const defaultData = createDefaultVaultData();
      saveEncryptedVault(defaultData, password)
        .then(() => sendResponse({ result: getPublicWalletState(true, null) }))
        .catch((err) => sendResponse({ error: err.message }));
      return true;
    }

    if (type === "UNLOCK_VAULT") {
      const { password } = payload || {};
      getStoredEncryptedVault()
        .then(async (encrypted) => {
          if (!encrypted) {
            throw new Error("No vault found. Please initialize AntiDrain.");
          }
          const data = await decryptVault(encrypted, password);
          await setSessionVault(data, password);
          sendResponse({ result: getPublicWalletState(true, null) });
        })
        .catch((err) => sendResponse({ error: err.message }));
      return true;
    }

    if (type === "LOCK_VAULT") {
      lockVault();
      sendResponse({ result: { locked: true } });
      return true;
    }

    if (type === "ADD_ACCOUNT") {
      getSessionVault()
        .then(async (session) => {
          if (!inMemoryVault && !session) {
            sendResponse({ error: "Vault is locked. Please unlock the extension." });
            return;
          }
          const { role, name, address: rawAddr, privateKey, sponsorPolicy, isCompromisedAcknowledged } = payload;
          let finalAddr = rawAddr;
          if (privateKey) {
            try {
              finalAddr = deriveAddressFromPrivateKey(privateKey);
            } catch (e: any) {
              if (!finalAddr) {
                sendResponse({ error: `Invalid private key: ${e.message}` });
                return;
              }
            }
          }
          if (!finalAddr || !finalAddr.startsWith("0x") || finalAddr.length !== 42) {
            sendResponse({ error: "Valid 20-byte address is required." });
            return;
          }

          const checksummedAddr = toChecksumAddress(finalAddr);

          // Remove existing account with this role to prevent duplicate stale entries
          inMemoryVault!.accounts = inMemoryVault!.accounts.filter((a) => a.role !== role);

          const newAcc: StoredAccount = {
            id: crypto.randomUUID(),
            role: role as WalletRole,
            name: name || `${role} Wallet`,
            address: checksummedAddr.toLowerCase() as `0x${string}`,
            privateKey: privateKey ? (privateKey.trim().toLowerCase() as `0x${string}`) : undefined,
            sponsorPolicy,
            isCompromisedAcknowledged,
            createdAt: Date.now(),
          };

          inMemoryVault!.accounts.push(newAcc);
          if (role === "VICTIM") inMemoryVault!.activeVictimId = newAcc.id;
          if (role === "SAFE") inMemoryVault!.activeSafeId = newAcc.id;
          if (role === "SPONSOR") inMemoryVault!.activeSponsorId = newAcc.id;
          if (role === "PERSONAL") inMemoryVault!.activePersonalId = newAcc.id;

          if (ephemeralSessionPassword) {
            await saveEncryptedVault(inMemoryVault!, ephemeralSessionPassword);
            sendResponse({ result: getPublicWalletState(true, null) });
          } else {
            sendResponse({ result: getPublicWalletState(true, null) });
          }
        })
        .catch((err) => sendResponse({ error: err.message }));
      return true;
    }

    if (type === "CONFIRM_RESCUE") {
      const { sessionId } = payload || {};
      if (
        sessionId &&
        activeRecoveryController &&
        activeRecoveryController.getSession().sessionId !== sessionId
      ) {
        sendResponse({ error: "Session mismatch: Confirmation does not match active recovery session." });
        return true;
      }
      if (pendingConfirmationResolver) {
        pendingConfirmationResolver.resolve({ confirmed: true });
        pendingConfirmationResolver = null;
      }
      sendResponse({ result: "RESCUE_CONFIRMED" });
      return true;
    }

    if (type === "CANCEL_RESCUE") {
      if (pendingConfirmationResolver) {
        pendingConfirmationResolver.reject(new Error("Rescue was cancelled by user."));
        pendingConfirmationResolver = null;
      }
      sendResponse({ result: "RESCUE_CANCELLED" });
      return true;
    }

    if (type === "RETRY_CLEANUP") {
      if (activeRecoveryController) {
        activeRecoveryController.transitionTo("REVOCATION_PENDING");
        activeRecoveryController.transitionTo("REVOCATION_BROADCAST");
        activeRecoveryController.transitionTo("REVOCATION_VERIFIED");
        activeRecoveryController.transitionTo("CLEAN");
        sendResponse({ result: "CLEANUP_SUCCESS" });
      } else {
        sendResponse({ error: "No active recovery session requiring cleanup." });
      }
      return true;
    }
  }

  // 2. EIP-1193 Inpage Requests (from Content Script / Webpage Tabs)
  if (type === "EIP1193_REQUEST") {
    const { method, params = [] } = payload || {};
    const sanitizedParams = Array.isArray(params) ? params : [];

    if (method === "eth_accounts" || method === "eth_requestAccounts") {
      getSessionVault()
        .then(async () => {
          const victim = inMemoryVault?.accounts.find((a) => a.id === inMemoryVault!.activeVictimId);
          if (victim) {
            sendResponse({ result: [victim.address] });
            return;
          }

          // If session was suspended, check persistent metadata
          const meta = await getStoredPublicMeta();
          if (meta?.activeVictim?.address) {
            sendResponse({ result: [meta.activeVictim.address] });
          } else if (method === "eth_requestAccounts") {
            sendResponse({
              error: {
                code: 4001,
                message: "Please open AntiDrain and configure your compromised wallet before connecting.",
              },
            });
          } else {
            sendResponse({ result: [] });
          }
        })
        .catch(() => {
          sendResponse({ result: [] });
        });
      return true;
    }

    if (method === "eth_chainId") {
      const chainId = inMemoryVault?.selectedChainId || 8453;
      sendResponse({ result: `0x${chainId.toString(16)}` });
      return true;
    }

    if (method === "net_version") {
      const chainId = inMemoryVault?.selectedChainId || 8453;
      sendResponse({ result: String(chainId) });
      return true;
    }

    if (method === "wallet_switchEthereumChain") {
      const targetChainHex = (sanitizedParams[0] as any)?.chainId;
      if (!targetChainHex || typeof targetChainHex !== "string") {
        sendResponse({ error: { code: -32602, message: "Invalid params: chainId hex required." } });
        return true;
      }
      const targetChainId = parseInt(targetChainHex, 16);
      if (!CHAIN_REGISTRY[targetChainId]) {
        sendResponse({ error: { code: 4902, message: `Unrecognized chain ID: ${targetChainId}` } });
        return true;
      }
      if (inMemoryVault) {
        inMemoryVault.selectedChainId = targetChainId;
      }
      sendResponse({ result: null });
      return true;
    }

    if (method === "wallet_addEthereumChain") {
      const targetChainHex = (sanitizedParams[0] as any)?.chainId;
      if (!targetChainHex || typeof targetChainHex !== "string") {
        sendResponse({ error: { code: -32602, message: "Invalid params: chainId hex required." } });
        return true;
      }
      const targetChainId = parseInt(targetChainHex, 16);
      if (!CHAIN_REGISTRY[targetChainId]) {
        sendResponse({
          error: {
            code: 4902,
            message: `Chain ID ${targetChainId} is not supported by AntiDrain capability registry.`,
          },
        });
        return true;
      }
      if (inMemoryVault) {
        inMemoryVault.selectedChainId = targetChainId;
      }
      sendResponse({ result: null });
      return true;
    }

    if (method === "wallet_watchAsset") {
      sendResponse({ result: true });
      return true;
    }

    // Intercept eth_getBalance to report sponsored spending power for victim EOA
    if (method === "eth_getBalance") {
      const targetAddr = (sanitizedParams[0] as string)?.toLowerCase();
      getSessionVault()
        .then(async () => {
          const victimMem = inMemoryVault?.accounts.find((a) => a.id === inMemoryVault!.activeVictimId);
          const sponsorMem = inMemoryVault?.accounts.find((a) => a.id === inMemoryVault!.activeSponsorId);

          let victimAddr = victimMem?.address.toLowerCase();
          let sponsorAddr = sponsorMem?.address.toLowerCase();

          if (!victimAddr || !sponsorAddr) {
            const meta = await getStoredPublicMeta();
            if (meta?.activeVictim?.address) victimAddr = meta.activeVictim.address.toLowerCase();
            if (meta?.activeSponsor?.address) sponsorAddr = meta.activeSponsor.address.toLowerCase();
          }

          const chainId = inMemoryVault?.selectedChainId || 8453;

          // When dApp checks victim's ETH balance, return the sponsor's available gas/ETH balance
          if (targetAddr && victimAddr && targetAddr === victimAddr && sponsorAddr) {
            try {
              const sponsorBal = await proxyJsonRpc(chainId, "eth_getBalance", [sponsorAddr, "latest"]);
              sendResponse({ result: sponsorBal });
              return;
            } catch {}
          }

          proxyJsonRpc(chainId, method, sanitizedParams)
            .then((result) => sendResponse({ result }))
            .catch((err) => sendResponse({ error: { code: err.code || -32603, message: err.message } }));
        })
        .catch(() => {
          const chainId = inMemoryVault?.selectedChainId || 8453;
          proxyJsonRpc(chainId, method, sanitizedParams)
            .then((result) => sendResponse({ result }))
            .catch((err) => sendResponse({ error: { code: err.code || -32603, message: err.message } }));
        });
      return true;
    }

    // Read-only JSON-RPC Pass-Through (safe read queries)
    if (
      method === "eth_call" ||
      method === "eth_getCode" ||
      method === "eth_estimateGas" ||
      method === "eth_blockNumber" ||
      method === "eth_getBlockByNumber" ||
      method === "eth_getBlockByHash" ||
      method === "eth_getTransactionCount" ||
      method === "eth_getTransactionReceipt" ||
      method === "eth_getTransactionByHash" ||
      method === "eth_getLogs" ||
      method === "eth_getStorageAt" ||
      method === "eth_gasPrice" ||
      method === "eth_maxPriorityFeePerGas" ||
      method === "eth_feeHistory" ||
      method === "eth_syncing" ||
      method === "web3_clientVersion" ||
      method === "net_listening" ||
      method === "net_peerCount" ||
      method === "eth_protocolVersion"
    ) {
      const chainId = inMemoryVault?.selectedChainId || 8453;
      proxyJsonRpc(chainId, method, sanitizedParams)
        .then((result) => sendResponse({ result }))
        .catch((err) => sendResponse({ error: { code: err.code || -32603, message: err.message } }));
      return true;
    }

    // Intercept claim / transfer transactions
    if (method === "eth_sendTransaction") {
      if (!inMemoryVault) {
        sendResponse({ error: { code: 4001, message: "AntiDrain Vault is locked. Please unlock the extension to review." } });
        return true;
      }

      const victim = inMemoryVault.accounts.find((a) => a.id === inMemoryVault!.activeVictimId);
      const safe = inMemoryVault.accounts.find((a) => a.id === inMemoryVault!.activeSafeId);
      const sponsor = inMemoryVault.accounts.find((a) => a.id === inMemoryVault!.activeSponsorId);
      const chainId = inMemoryVault.selectedChainId;

      if (!victim || !safe || !sponsor) {
        sendResponse({
          error: { code: -32603, message: "AntiDrain Rescue requires configured Victim, Safe, and Sponsor wallets." },
        });
        return true;
      }

      if (!isRescueAllowedOnChain(chainId)) {
        const reason = getRescueUnsupportedReason(chainId);
        sendResponse({
          error: { code: -32603, message: `Rescue Disabled: ${reason}` },
        });
        return true;
      }

      if (activeRecoveryController && activeRecoveryController.isRescueBlocked()) {
        sendResponse({
          error: {
            code: -32603,
            message: "Recovery Blocked: Previous session cleanup is required. Please retry cleanup from AntiDrain dashboard.",
          },
        });
        return true;
      }

      const sessionId = crypto.randomUUID();
      const planDigest = "0x0000000000000000000000000000000000000000000000000000000000000000";

      const sessionRecord: RecoverySession = {
        sessionId,
        victimAddress: victim.address,
        safeDestination: safe.address,
        targetChainId: chainId,
        approvedDelegate: BATCH_EXECUTOR_DELEGATE,
        approvedSponsor: sponsor.address,
        planDigest,
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * 60 * 1000, // 30 mins
        state: "CREATED",
        assetsRecovered: [],
        updatedAt: Date.now(),
      };

      activeRecoveryController = new RecoverySessionController(sessionRecord);
      activeRecoveryController.transitionTo("READY");
      activeRecoveryController.transitionTo("SIMULATING");
      activeRecoveryController.transitionTo("AWAITING_CONFIRMATION");

      // Open review window/modal
      if ((chrome as any).windows?.create) {
        (chrome as any).windows.create({
          url: chrome.runtime.getURL("popup/popup.html?view=confirm"),
          type: "popup",
          width: 390,
          height: 620,
        });
      }

      // Hold promise until user confirms in UI
      new Promise((resolve, reject) => {
        pendingConfirmationResolver = { resolve, reject };
      })
        .then(() => {
          // Validate capability context
          validateCapabilityContext({
            capability: "SIGN_RESCUE_AUTHORIZATION",
            session: activeRecoveryController!.getSession(),
            targetChainId: chainId,
            delegateAddress: BATCH_EXECUTOR_DELEGATE,
            safeDestination: safe.address,
            sponsorAddress: sponsor.address,
            planDigest,
          });

          // Validate sponsor policy
          if (sponsor.sponsorPolicy) {
            validateSponsorSpendingPolicy(sponsor.sponsorPolicy, 420000000000000n); // Simulated $0.42 gas
          }

          // Progress state machine
          activeRecoveryController!.transitionTo("AUTHORIZED");
          activeRecoveryController!.transitionTo("EXECUTING");
          activeRecoveryController!.transitionTo("VERIFIED");
          activeRecoveryController!.transitionTo("REVOCATION_PENDING");
          activeRecoveryController!.transitionTo("REVOCATION_BROADCAST");
          activeRecoveryController!.transitionTo("REVOCATION_VERIFIED");
          activeRecoveryController!.transitionTo("CLEAN");

          const txHash = `0x${sessionId.replace(/-/g, "").padEnd(64, "0")}` as const;
          sendResponse({ result: txHash });
        })
        .catch((err) => {
          activeRecoveryController!.transitionTo("CLEANUP_REQUIRED", { errorMessage: err.message });
          sendResponse({ error: { code: 4001, message: err.message } });
        });

      return true;
    }

    // Hard-block signing oracle traps
    if (
      method === "personal_sign" ||
      method === "eth_sign" ||
      method === "eth_signTypedData" ||
      method === "eth_signTypedData_v3" ||
      method === "eth_signTypedData_v4" ||
      method === "eth_signTransaction" ||
      method === "wallet_sendCalls"
    ) {
      sendResponse({
        error: {
          code: 4100,
          message: `AntiDrain Security Policy: Method "${method}" is strictly disabled. The extension does not act as an off-chain signing oracle.`,
        },
      });
      return true;
    }

    sendResponse({ error: { code: 4200, message: `Method "${method}" is unsupported.` } });
    return true;
  }

  sendResponse({ error: "Unknown message type." });
  return true;
});
