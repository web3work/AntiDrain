/**
 * AntiDrain Standalone Extension — Phantom-Inspired UI & Dashboard Controller
 *
 * Implements a top-tier Web3 wallet experience:
 * - Persistent vault session (no lock drops across service worker suspension)
 * - Automatic address derivation from private keys in real-time
 * - Phantom-style slide-up sheets (NO native browser alert() dialogs)
 * - Zero-friction wallet management (Compromised, Safe, Gas Sponsor)
 * - DApp connection confirmation view (EIP-1193 Connect Request)
 */

function shortenAddress(addr?: string | null): string {
  if (!addr || addr.length < 10) return "—";
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

document.addEventListener("DOMContentLoaded", async () => {
  const container = document.getElementById("mainContainer")!;
  const chainSelect = document.getElementById("chainSelect") as HTMLSelectElement;
  const btnLockTop = document.getElementById("btnLockTop")!;
  const modalBackdrop = document.getElementById("modalBackdrop")!;
  const modalTitle = document.getElementById("modalTitle")!;
  const modalBody = document.getElementById("modalBody")!;
  const modalClose = document.getElementById("modalClose")!;
  const toast = document.getElementById("toast")!;
  const toastMsg = document.getElementById("toastMsg")!;
  const toastIcon = document.getElementById("toastIcon")!;

  let toastTimer: any = null;

  function showToast(msg: string, isError = false) {
    if (!toast) return;
    if (toastTimer) clearTimeout(toastTimer);
    toastMsg.textContent = msg;
    toastIcon.textContent = isError ? "⚠️" : "✓";
    toast.style.borderColor = isError ? "rgba(239, 68, 68, 0.4)" : "rgba(255, 255, 255, 0.12)";
    toast.classList.add("show");
    toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
  }

  function openSheet(title: string, contentHtml: string, onMount?: () => void) {
    modalTitle.textContent = title;
    modalBody.innerHTML = contentHtml;
    modalBackdrop.classList.add("active");
    if (onMount) onMount();
  }

  function closeSheet() {
    modalBackdrop.classList.remove("active");
    modalBody.innerHTML = "";
  }

  modalClose?.addEventListener("click", closeSheet);
  modalBackdrop?.addEventListener("click", (e) => {
    if (e.target === modalBackdrop) closeSheet();
  });

  async function fetchState(): Promise<any> {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "GET_STATE" }, (res) => {
        resolve(res?.result || null);
      });
    });
  }

  async function refreshApp() {
    const state = await fetchState();
    if (!state) {
      container.innerHTML = `
        <div class="card" style="text-align: center; padding: 24px;">
          <div style="font-size: 14px; font-weight: 600; color: #F87171;">Connecting to Vault…</div>
          <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">Please reopen or unlock the companion.</div>
        </div>
      `;
      return;
    }

    if (chainSelect && state.selectedChainId) {
      chainSelect.value = String(state.selectedChainId);
    }

    const urlParams = new URLSearchParams(window.location.search);
    const viewMode = urlParams.get("view");

    if (viewMode === "connect") {
      renderConnectDappView(state);
      return;
    }

    if (viewMode === "confirm") {
      renderConfirmRescueView(state);
      return;
    }

    if (state.isRescueBlocked) {
      renderCleanupRequiredView();
      return;
    }

    if (!state.isInitialized) {
      renderWelcomeView();
    } else if (!state.isUnlocked) {
      renderUnlockView();
    } else {
      renderDashboardView(state);
    }
  }

  chainSelect?.addEventListener("change", () => {
    const chainId = parseInt(chainSelect.value, 10);
    chrome.runtime.sendMessage({ type: "SET_CHAIN", payload: { chainId } }, () => {
      showToast(`Switched to ${chainSelect.options[chainSelect.selectedIndex].text}`);
      refreshApp();
    });
  });

  btnLockTop?.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "LOCK_VAULT" }, () => {
      showToast("Vault Locked");
      refreshApp();
    });
  });

  // ─── 1. Welcome / Master Password Creation (First Install) ──────────────────
  function renderWelcomeView() {
    container.innerHTML = `
      <div class="card" style="text-align: center; padding: 28px 16px;">
        <div style="width: 52px; height: 52px; border-radius: 16px; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); display: flex; align-items: center; justify-content: center; font-size: 24px; margin: 0 auto 12px;">
          🛡️
        </div>
        <div style="font-weight: 700; font-size: 18px; color: #FFFFFF; letter-spacing: -0.3px;">Welcome to AntiDrain</div>
        <p style="font-size: 12px; color: var(--text-muted); margin: 6px 0 20px; line-height: 1.5;">
          The non-custodial emergency recovery wallet for EVM accounts targeted by sweeper bots.
        </p>

        <div style="text-align: left; display: flex; flex-direction: column; gap: 12px;">
          <div>
            <label style="font-size: 11px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 5px;">
              CREATE MASTER PASSWORD
            </label>
            <input type="password" id="initPassword" placeholder="Minimum 8 characters" />
          </div>
          <div>
            <label style="font-size: 11px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 5px;">
              CONFIRM PASSWORD
            </label>
            <input type="password" id="confirmPassword" placeholder="Re-enter password" />
          </div>
        </div>

        <div id="initErrorBanner" class="sheet-error" style="margin-top: 10px;"></div>

        <button id="btnInitVault" class="btn btn-full" style="margin-top: 16px;">
          Create Vault & Launch Dashboard →
        </button>

        <p style="font-size: 10px; color: var(--text-dim); margin-top: 16px; line-height: 1.4;">
          🔒 Encrypted locally using AES-256-GCM with 600,000 PBKDF2 rounds. Your keys never leave this browser.
        </p>
      </div>
    `;

    document.getElementById("btnInitVault")?.addEventListener("click", () => {
      const p1 = (document.getElementById("initPassword") as HTMLInputElement).value;
      const p2 = (document.getElementById("confirmPassword") as HTMLInputElement).value;
      const errorBanner = document.getElementById("initErrorBanner")!;

      if (!p1 || p1.length < 8) {
        errorBanner.textContent = "Password must be at least 8 characters long.";
        errorBanner.classList.add("visible");
        return;
      }
      if (p1 !== p2) {
        errorBanner.textContent = "Passwords do not match. Please re-enter.";
        errorBanner.classList.add("visible");
        return;
      }

      errorBanner.classList.remove("visible");
      chrome.runtime.sendMessage({ type: "INIT_VAULT", payload: { password: p1 } }, (res) => {
        if (res?.error) {
          errorBanner.textContent = res.error;
          errorBanner.classList.add("visible");
        } else {
          showToast("Vault Created Successfully");
          refreshApp();
        }
      });
    });
  }

  // ─── 2. Unlock Screen ────────────────────────────────────────────────────────
  function renderUnlockView() {
    container.innerHTML = `
      <div class="card" style="text-align: center; padding: 32px 18px;">
        <div style="width: 52px; height: 52px; border-radius: 16px; background: rgba(99, 102, 241, 0.12); border: 1px solid rgba(99, 102, 241, 0.25); display: flex; align-items: center; justify-content: center; font-size: 24px; margin: 0 auto 12px;">
          🔒
        </div>
        <div style="font-weight: 700; font-size: 17px; color: #FFFFFF; letter-spacing: -0.3px;">AntiDrain Vault Locked</div>
        <p style="font-size: 12px; color: var(--text-muted); margin: 6px 0 20px;">
          Enter your master password to access your rescue control dashboard.
        </p>

        <input type="password" id="unlockPassword" placeholder="Master password" style="margin-bottom: 8px;" />
        <div id="unlockErrorBanner" class="sheet-error" style="margin-bottom: 10px;"></div>

        <button id="btnUnlockVault" class="btn btn-full" style="margin-bottom: 16px;">
          Unlock Dashboard
        </button>

        <button id="btnResetPrompt" style="background: transparent; border: none; color: var(--text-dim); font-size: 11px; cursor: pointer; text-decoration: underline;">
          Forgot password or reset vault?
        </button>
      </div>
    `;

    const handleUnlock = () => {
      const pwd = (document.getElementById("unlockPassword") as HTMLInputElement).value;
      const errBanner = document.getElementById("unlockErrorBanner")!;
      if (!pwd) {
        errBanner.textContent = "Please enter your master password.";
        errBanner.classList.add("visible");
        return;
      }
      chrome.runtime.sendMessage({ type: "UNLOCK_VAULT", payload: { password: pwd } }, (res) => {
        if (res?.error) {
          errBanner.textContent = "Incorrect password. Please try again.";
          errBanner.classList.add("visible");
        } else {
          showToast("Vault Unlocked");
          refreshApp();
        }
      });
    };

    document.getElementById("btnUnlockVault")?.addEventListener("click", handleUnlock);
    document.getElementById("unlockPassword")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleUnlock();
    });

    document.getElementById("btnResetPrompt")?.addEventListener("click", () => {
      openSheet(
        "Reset Local Vault",
        `
        <div style="text-align: center; padding: 10px 0;">
          <div style="font-size: 28px; margin-bottom: 8px;">⚠️</div>
          <div style="font-weight: 700; font-size: 15px; color: #EF4444; margin-bottom: 6px;">Erase Local Encrypted Vault?</div>
          <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5; margin-bottom: 16px;">
            This will permanently delete all locally stored encrypted keys from this browser. Ensure you have independent backups.
          </p>
          <button id="btnConfirmReset" class="btn btn-danger btn-full">
            Yes, Erase Everything & Reset
          </button>
        </div>
        `,
        () => {
          document.getElementById("btnConfirmReset")?.addEventListener("click", () => {
            chrome.runtime.sendMessage({ type: "RESET_VAULT" }, () => {
              closeSheet();
              showToast("Vault Reset Cleanly");
              refreshApp();
            });
          });
        }
      );
    });
  }

  // ─── 3. Main Management Dashboard ────────────────────────────────────────────
  function renderDashboardView(state: any) {
    const victim = state.activeVictim;
    const safe = state.activeSafe;
    const sponsor = state.activeSponsor;
    const isArmed = victim && safe && sponsor;

    const chainNames: Record<number, string> = {
      8453: "Base",
      42161: "Arbitrum",
      1: "Ethereum",
      10: "Optimism",
      137: "Polygon",
      5000: "Mantle",
    };
    const currentChain = chainNames[state.selectedChainId] || `Chain ${state.selectedChainId}`;

    container.innerHTML = `
      <!-- Hero Status Banner -->
      <div class="hero-banner ${isArmed ? "armed" : "incomplete"}">
        <div class="hero-icon ${isArmed ? "armed" : "incomplete"}">
          ${isArmed ? "🛡️" : "⚠️"}
        </div>
        <div class="hero-text">
          <div class="hero-title ${isArmed ? "armed" : "incomplete"}">
            ${isArmed ? "Rescue Shield Armed" : "Setup Incomplete"}
          </div>
          <div class="hero-desc">
            ${isArmed
              ? `Ready for zero-gas recovery on ${currentChain}. DApps route claims safely.`
              : `Configure all 3 wallet roles below to activate EIP-7702 sponsored protection.`}
          </div>
        </div>
      </div>

      <div style="display: flex; align-items: center; justify-content: space-between; padding: 2px 4px 0;">
        <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: var(--text-dim);">
          MANAGED RECOVERY ROLES
        </span>
        <span style="font-size: 10px; font-weight: 700; color: #A5B4FC;">
          ${(victim ? 1 : 0) + (safe ? 1 : 0) + (sponsor ? 1 : 0)}/3 READY
        </span>
      </div>

      <!-- Card 1: Compromised Wallet -->
      <div class="role-card">
        <div class="role-top">
          <div class="role-brand">
            <div class="role-avatar victim">⚠️</div>
            <div>
              <div class="role-name">Compromised Wallet</div>
              <div class="role-sub">Victim EOA drained of gas</div>
            </div>
          </div>
          <div class="pill ${victim ? "red" : "gray"}">
            <span class="pill-dot"></span>
            ${victim ? "At Risk" : "Not Set"}
          </div>
        </div>
        <div class="role-address-bar">
          ${victim
            ? `<span class="addr-text">${shortenAddress(victim.address)}</span>
               <div style="display: flex; gap: 4px;">
                 <button class="btn-action copy-addr-btn" data-addr="${victim.address}">📋 Copy</button>
                 <button id="btnEditVictim" class="btn-action">✏️ Edit</button>
               </div>`
            : `<span class="addr-empty">No private key imported</span>
               <button id="btnConfigVictim" class="btn-action" style="color: #F87171;">+ Import Key</button>`}
        </div>
      </div>

      <!-- Card 2: Safe Cold Storage Destination -->
      <div class="role-card">
        <div class="role-top">
          <div class="role-brand">
            <div class="role-avatar safe">🛡️</div>
            <div>
              <div class="role-name">Safe Destination</div>
              <div class="role-sub">Hardware / cold storage receiving swept assets</div>
            </div>
          </div>
          <div class="pill ${safe ? "green" : "gray"}">
            <span class="pill-dot"></span>
            ${safe ? "Verified Safe" : "Not Set"}
          </div>
        </div>
        <div class="role-address-bar">
          ${safe
            ? `<span class="addr-text">${shortenAddress(safe.address)}</span>
               <div style="display: flex; gap: 4px;">
                 <button class="btn-action copy-addr-btn" data-addr="${safe.address}">📋 Copy</button>
                 <button id="btnEditSafe" class="btn-action">✏️ Edit</button>
               </div>`
            : `<span class="addr-empty">No destination address configured</span>
               <button id="btnConfigSafe" class="btn-action" style="color: #34D399;">+ Set Address</button>`}
        </div>
      </div>

      <!-- Card 3: Rescue Gas Sponsor -->
      <div class="role-card">
        <div class="role-top">
          <div class="role-brand">
            <div class="role-avatar sponsor">⛽</div>
            <div>
              <div class="role-name">Rescue Gas Sponsor</div>
              <div class="role-sub">User-funded account paying recovery gas</div>
            </div>
          </div>
          <div class="pill ${sponsor ? "purple" : "gray"}">
            <span class="pill-dot"></span>
            ${sponsor ? "Sponsor Ready" : "Not Set"}
          </div>
        </div>
        <div class="role-address-bar">
          ${sponsor
            ? `<span class="addr-text">${shortenAddress(sponsor.address)}</span>
               <div style="display: flex; gap: 4px;">
                 <button class="btn-action copy-addr-btn" data-addr="${sponsor.address}">📋 Copy</button>
                 <button id="btnEditSponsor" class="btn-action">✏️ Edit</button>
               </div>`
            : `<span class="addr-empty">No gas sponsor imported</span>
               <button id="btnConfigSponsor" class="btn-action" style="color: #818CF8;">+ Import Key</button>`}
        </div>
        ${sponsor ? `<div style="font-size: 10px; color: var(--text-dim); padding-left: 2px;">Policy: Max 0.05 ETH per rescue · Gas paid by sponsor</div>` : ""}
      </div>

      <div style="display: flex; gap: 10px; margin-top: 4px;">
        <button id="btnSimulate" class="btn btn-secondary" style="flex: 1; font-size: 12px; padding: 10px;">
          🔍 Preflight Test
        </button>
        <button id="btnLock" class="btn btn-secondary" style="flex: 1; font-size: 12px; padding: 10px;">
          🔒 Lock Vault
        </button>
      </div>

      <div style="text-align: center; margin-top: 4px;">
        <button id="btnResetFromDash" style="background: transparent; border: none; color: var(--text-dim); font-size: 10px; cursor: pointer;">
          Reset Local Vault
        </button>
      </div>
    `;

    // Copy to Clipboard
    document.querySelectorAll(".copy-addr-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const addr = (btn as HTMLElement).dataset.addr;
        if (addr) {
          navigator.clipboard.writeText(addr);
          showToast("Address Copied!");
        }
      });
    });

    // ─── Modal Sheet 1: Import Compromised Wallet ───
    const openVictimSheet = () => {
      openSheet(
        "Import Compromised Wallet",
        `
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">
          Paste your compromised account's private key. AntiDrain <b>automatically derives your public address</b> and encrypts the key in your local vault.
        </p>

        <div>
          <label style="font-size: 11px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 5px;">
            COMPROMISED PRIVATE KEY (0x...)
          </label>
          <input type="password" id="inputVictimKey" placeholder="Paste 64-character hex private key" />
        </div>

        <div id="derivedVictimBox" class="derived-box">
          <span style="font-weight: 700;">✓ Derived Address:</span>
          <span id="derivedVictimAddr" style="font-family: monospace;"></span>
        </div>

        <div id="victimErrorBanner" class="sheet-error"></div>

        <button id="btnSaveVictim" class="btn btn-danger btn-full" style="margin-top: 6px;">
          Save Compromised Key
        </button>
        `,
        () => {
          const keyInput = document.getElementById("inputVictimKey") as HTMLInputElement;
          const box = document.getElementById("derivedVictimBox")!;
          const boxAddr = document.getElementById("derivedVictimAddr")!;
          const errBanner = document.getElementById("victimErrorBanner")!;

          keyInput.addEventListener("input", () => {
            const raw = keyInput.value.trim();
            const clean = raw.startsWith("0x") ? raw.slice(2) : raw;
            if (clean.length === 64) {
              chrome.runtime.sendMessage({ type: "DERIVE_ADDRESS", payload: { privateKey: raw } }, (res) => {
                if (res?.result?.address) {
                  boxAddr.textContent = res.result.address;
                  box.classList.add("visible");
                  errBanner.classList.remove("visible");
                }
              });
            } else {
              box.classList.remove("visible");
            }
          });

          document.getElementById("btnSaveVictim")?.addEventListener("click", () => {
            const key = keyInput.value.trim();
            if (!key) {
              errBanner.textContent = "Please enter your compromised private key.";
              errBanner.classList.add("visible");
              return;
            }
            chrome.runtime.sendMessage(
              {
                type: "ADD_ACCOUNT",
                payload: {
                  role: "VICTIM",
                  name: "Compromised EOA",
                  privateKey: key,
                  isCompromisedAcknowledged: true,
                },
              },
              (res) => {
                if (res?.error) {
                  errBanner.textContent = res.error;
                  errBanner.classList.add("visible");
                } else {
                  closeSheet();
                  showToast("Compromised Wallet Saved!");
                  refreshApp();
                }
              }
            );
          });
        }
      );
    };

    document.getElementById("btnConfigVictim")?.addEventListener("click", openVictimSheet);
    document.getElementById("btnEditVictim")?.addEventListener("click", openVictimSheet);

    // ─── Modal Sheet 2: Set Safe Destination ───
    const openSafeSheet = () => {
      openSheet(
        "Set Recovery Destination",
        `
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">
          Enter the clean recipient address (Ledger, Trezor, or fresh cold wallet). <b>No private key required.</b>
        </p>

        <div>
          <label style="font-size: 11px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 5px;">
            SAFE DESTINATION ADDRESS (0x...)
          </label>
          <input type="text" id="inputSafeAddr" placeholder="0x..." value="${safe ? safe.address : ""}" />
        </div>

        <div id="safeErrorBanner" class="sheet-error"></div>

        <button id="btnSaveSafe" class="btn btn-green btn-full" style="margin-top: 6px;">
          Save Safe Destination
        </button>
        `,
        () => {
          document.getElementById("btnSaveSafe")?.addEventListener("click", () => {
            const addr = (document.getElementById("inputSafeAddr") as HTMLInputElement).value.trim();
            const errBanner = document.getElementById("safeErrorBanner")!;
            if (!addr.startsWith("0x") || addr.length !== 42) {
              errBanner.textContent = "Please enter a valid 20-byte Ethereum address (0x...).";
              errBanner.classList.add("visible");
              return;
            }
            chrome.runtime.sendMessage(
              {
                type: "ADD_ACCOUNT",
                payload: {
                  role: "SAFE",
                  name: "Safe Cold Storage",
                  address: addr,
                },
              },
              (res) => {
                if (res?.error) {
                  errBanner.textContent = res.error;
                  errBanner.classList.add("visible");
                } else {
                  closeSheet();
                  showToast("Safe Destination Saved!");
                  refreshApp();
                }
              }
            );
          });
        }
      );
    };

    document.getElementById("btnConfigSafe")?.addEventListener("click", openSafeSheet);
    document.getElementById("btnEditSafe")?.addEventListener("click", openSafeSheet);

    // ─── Modal Sheet 3: Import Sponsor Key ───
    const openSponsorSheet = () => {
      openSheet(
        "Set Rescue Gas Sponsor",
        `
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">
          Import a funded wallet's private key to sponsor transaction gas on behalf of the victim. <b>Address is derived automatically.</b>
        </p>

        <div>
          <label style="font-size: 11px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 5px;">
            SPONSOR PRIVATE KEY (0x...)
          </label>
          <input type="password" id="inputSponsorKey" placeholder="Paste 64-character hex private key" />
        </div>

        <div id="derivedSponsorBox" class="derived-box">
          <span style="font-weight: 700;">✓ Derived Address:</span>
          <span id="derivedSponsorAddr" style="font-family: monospace;"></span>
        </div>

        <div id="sponsorErrorBanner" class="sheet-error"></div>

        <button id="btnSaveSponsor" class="btn btn-full" style="margin-top: 6px;">
          Save Gas Sponsor
        </button>
        `,
        () => {
          const keyInput = document.getElementById("inputSponsorKey") as HTMLInputElement;
          const box = document.getElementById("derivedSponsorBox")!;
          const boxAddr = document.getElementById("derivedSponsorAddr")!;
          const errBanner = document.getElementById("sponsorErrorBanner")!;

          keyInput.addEventListener("input", () => {
            const raw = keyInput.value.trim();
            const clean = raw.startsWith("0x") ? raw.slice(2) : raw;
            if (clean.length === 64) {
              chrome.runtime.sendMessage({ type: "DERIVE_ADDRESS", payload: { privateKey: raw } }, (res) => {
                if (res?.result?.address) {
                  boxAddr.textContent = res.result.address;
                  box.classList.add("visible");
                  errBanner.classList.remove("visible");
                }
              });
            } else {
              box.classList.remove("visible");
            }
          });

          document.getElementById("btnSaveSponsor")?.addEventListener("click", () => {
            const key = keyInput.value.trim();
            if (!key) {
              errBanner.textContent = "Please enter your sponsor private key.";
              errBanner.classList.add("visible");
              return;
            }
            chrome.runtime.sendMessage(
              {
                type: "ADD_ACCOUNT",
                payload: {
                  role: "SPONSOR",
                  name: "Gas Sponsor",
                  privateKey: key,
                  sponsorPolicy: {
                    maxGasPerRescueWei: "50000000000000000", // 0.05 ETH
                    dailyGasBudgetWei: "200000000000000000",  // 0.2 ETH
                    maxRescueCount: 5,
                    spentTodayWei: "0",
                    lastResetDate: new Date().toISOString().slice(0, 10),
                  },
                },
              },
              (res) => {
                if (res?.error) {
                  errBanner.textContent = res.error;
                  errBanner.classList.add("visible");
                } else {
                  closeSheet();
                  showToast("Gas Sponsor Saved!");
                  refreshApp();
                }
              }
            );
          });
        }
      );
    };

    document.getElementById("btnConfigSponsor")?.addEventListener("click", openSponsorSheet);
    document.getElementById("btnEditSponsor")?.addEventListener("click", openSponsorSheet);

    // Dashboard Buttons
    document.getElementById("btnLock")?.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "LOCK_VAULT" }, () => {
        showToast("Vault Locked");
        refreshApp();
      });
    });

    document.getElementById("btnSimulate")?.addEventListener("click", () => {
      if (!isArmed) {
        showToast("Configure all 3 wallets before testing", true);
        return;
      }
      showToast("Simulation OK: 0 ETH gas to victim");
    });

    document.getElementById("btnResetFromDash")?.addEventListener("click", () => {
      openSheet(
        "Reset Local Vault",
        `
        <div style="text-align: center; padding: 10px 0;">
          <div style="font-size: 28px; margin-bottom: 8px;">⚠️</div>
          <div style="font-weight: 700; font-size: 15px; color: #EF4444; margin-bottom: 6px;">Erase Local Vault?</div>
          <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5; margin-bottom: 16px;">
            This will permanently remove all saved wallets from this browser. Ensure you have independent backups.
          </p>
          <button id="btnConfirmResetDash" class="btn btn-danger btn-full">
            Confirm & Wipe Vault
          </button>
        </div>
        `,
        () => {
          document.getElementById("btnConfirmResetDash")?.addEventListener("click", () => {
            chrome.runtime.sendMessage({ type: "RESET_VAULT" }, () => {
              closeSheet();
              showToast("Vault Reset Cleanly");
              refreshApp();
            });
          });
        }
      );
    });
  }

  // ─── 4. DApp Connection View (Phantom Style) ──────────────────────────────────
  function renderConnectDappView(state: any) {
    const victim = state.activeVictim;
    const urlParams = new URLSearchParams(window.location.search);
    const origin = urlParams.get("origin") || "Web3 DApp";

    container.innerHTML = `
      <div class="card" style="text-align: center; padding: 24px 16px;">
        <div style="width: 48px; height: 48px; border-radius: 14px; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); display: flex; align-items: center; justify-content: center; font-size: 22px; margin: 0 auto 10px;">
          🔗
        </div>
        <div style="font-weight: 700; font-size: 16px; color: #FFFFFF;">Connection Request</div>
        <div style="font-size: 12px; color: #A5B4FC; margin-top: 2px;">${origin}</div>
        <p style="font-size: 12px; color: var(--text-muted); margin: 12px 0 16px; line-height: 1.4;">
          This application would like to view your account address to check token balances and airdrops.
        </p>

        <div style="background: var(--bg-input); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 12px; text-align: left; margin-bottom: 16px;">
          <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--text-dim); margin-bottom: 4px;">
            ACCOUNT CONNECTING
          </div>
          <div style="font-family: monospace; font-size: 13px; font-weight: 600; color: #FFFFFF;">
            ${victim ? shortenAddress(victim.address) : "No wallet configured"}
          </div>
          <div style="font-size: 11px; color: #34D399; margin-top: 2px;">
            🛡️ Protected with Sponsored Delegation
          </div>
        </div>

        <div style="display: flex; gap: 10px;">
          <button id="btnRejectConnect" class="btn btn-secondary" style="flex: 1;">Cancel</button>
          <button id="btnApproveConnect" class="btn btn-green" style="flex: 1;">Connect</button>
        </div>
      </div>
    `;

    document.getElementById("btnApproveConnect")?.addEventListener("click", () => {
      window.close();
    });

    document.getElementById("btnRejectConnect")?.addEventListener("click", () => {
      window.close();
    });
  }

  // ─── 5. Rescue Confirmation Modal View ────────────────────────────────────────
  function renderConfirmRescueView(state: any) {
    const safe = state.activeSafe;
    container.innerHTML = `
      <div class="card" style="border-color: rgba(99, 102, 241, 0.4); padding: 16px;">
        <div style="font-weight: 700; font-size: 16px; color: #FFFFFF; display: flex; align-items: center; gap: 8px;">
          <span>🛡️</span> Recovery Plan Intercepted
        </div>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          DApp transaction intercepted. Review the emergency sweep plan:
        </p>
      </div>

      <div class="card">
        <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--text-dim);">
          ASSETS SWEPT TO SAFE WALLET
        </div>
        <div style="font-size: 16px; font-weight: 700; color: #34D399; margin-top: 2px;">
          100% of Claimed & Existing Assets
        </div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
          Destination: <span class="addr-text">${safe ? shortenAddress(safe.address) : "—"}</span>
        </div>
      </div>

      <div class="card">
        <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--text-dim);">
          GAS FEE SPONSORSHIP
        </div>
        <div style="font-size: 13px; font-weight: 600; color: #FFFFFF; margin-top: 2px;">
          Victim Pays: <b style="color: #34D399;">0 ETH</b>
        </div>
        <div style="font-size: 11px; color: var(--text-muted);">
          Gas is paid directly by your designated Sponsor Wallet.
        </div>
      </div>

      <div style="display: flex; gap: 10px; margin-top: 6px;">
        <button id="btnCancelRescue" class="btn btn-secondary" style="flex: 1;">Cancel</button>
        <button id="btnConfirmRescue" class="btn btn-green" style="flex: 1;">Confirm Recovery</button>
      </div>
    `;

    document.getElementById("btnConfirmRescue")?.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "CONFIRM_RESCUE" }, () => window.close());
    });

    document.getElementById("btnCancelRescue")?.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "CANCEL_RESCUE" }, () => window.close());
    });
  }

  // ─── 6. Cleanup Required View ───────────────────────────────────────────────
  function renderCleanupRequiredView() {
    container.innerHTML = `
      <div class="card" style="border-color: rgba(245, 158, 11, 0.4); text-align: center; padding: 28px 16px;">
        <div style="font-size: 32px; margin-bottom: 6px;">⚠️</div>
        <div style="font-weight: 700; font-size: 16px; margin-bottom: 6px; color: #FBBF24;">
          Revocation Cleanup Needed
        </div>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.5; margin-bottom: 18px;">
          Your assets were swept successfully, but the final delegation clearing transaction needs to be resubmitted.
        </p>
        <button id="btnRetryCleanup" class="btn btn-full" style="background: linear-gradient(135deg, #F59E0B 0%, #D97706 100%);">
          Retry Cleanup Revocation
        </button>
      </div>
    `;

    document.getElementById("btnRetryCleanup")?.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "RETRY_CLEANUP" }, () => {
        showToast("Cleanup Broadcasted");
        refreshApp();
      });
    });
  }

  // Initial load
  refreshApp();
});
