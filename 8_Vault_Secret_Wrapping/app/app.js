const vaultAddressInput = document.querySelector("#vault-address");
const namespaceInput = document.querySelector("#vault-namespace");
const wrapTokenInput = document.querySelector("#wrap-token");
const unwrapButton = document.querySelector("#unwrap-button");
const resetButton = document.querySelector("#reset-button");
const statusElement = document.querySelector("#status");
const resultOutput = document.querySelector("#result-output");
const resultState = document.querySelector("#result-state");

const defaults = {
  vaultAddress: "",
  namespace: "admin",
};

function setStatus(message, isError = false) {
  statusElement.textContent = message;
  statusElement.classList.toggle("error", isError);
}

function formatPayload(payload) {
  return JSON.stringify(payload, null, 2);
}

function normalizeVaultAddress(value) {
  return value.trim().replace(/\/+$/, "");
}

function saveInputs() {
  localStorage.setItem("wrappingDemoVaultAddress", vaultAddressInput.value.trim());
  localStorage.setItem("wrappingDemoVaultNamespace", namespaceInput.value.trim());
}

function loadInputs() {
  vaultAddressInput.value = localStorage.getItem("wrappingDemoVaultAddress") || defaults.vaultAddress;
  namespaceInput.value = localStorage.getItem("wrappingDemoVaultNamespace") || defaults.namespace;
}

async function unwrapToken() {
  const vaultAddress = normalizeVaultAddress(vaultAddressInput.value);
  const namespace = namespaceInput.value.trim();
  const wrapToken = wrapTokenInput.value.trim();

  if (!vaultAddress) {
    setStatus("Enter the Vault address before unwrapping.", true);
    return;
  }

  if (!wrapToken) {
    setStatus("Paste a wrapping token before unwrapping.", true);
    return;
  }

  saveInputs();
  unwrapButton.disabled = true;
  resultState.textContent = "unwrapping";
  setStatus("Calling Vault sys/wrapping/unwrap...");

  try {
    const response = await fetch("/unwrap", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        vaultAddress,
        namespace,
        wrapToken,
      }),
    });

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      const message = payload.errors?.join("; ") || `Vault returned HTTP ${response.status}`;
      throw new Error(message);
    }

    resultOutput.textContent = formatPayload(payload.data || payload);
    resultState.textContent = "unwrapped";
    setStatus("Secret unwrapped. This wrapping token cannot be used again.");
    wrapTokenInput.value = "";
  } catch (error) {
    resultState.textContent = "error";
    setStatus(error.message, true);
  } finally {
    unwrapButton.disabled = false;
  }
}

function resetForm() {
  wrapTokenInput.value = "";
  resultOutput.textContent = "{}";
  resultState.textContent = "empty";
  setStatus("Waiting for a wrapping token.");
}

loadInputs();
unwrapButton.addEventListener("click", unwrapToken);
resetButton.addEventListener("click", resetForm);