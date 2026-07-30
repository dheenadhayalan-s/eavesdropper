# 🌐 EaveGuard — 2-Laptop & 3-Laptop Network File Transmission Guide

This guide explains how to demonstrate **EaveGuard BB84 Quantum Key Distribution (QKD) & Secure File Transmission** across **2 or 3 separate laptops** over Wi-Fi or LAN networks.

---

## 📡 3-Laptop Network Topology

```
                  ┌────────────────────────┐
                  │   LAPTOP A (Alice)     │
                  │   Transmitter Mode     │
                  └───────────┬────────────┘
                              │ Sends Qubits
                              ▼
┌───────────────────────────────────────────────────────────┐
│                    LAPTOP C (Eve)                         │
│             Man-In-The-Middle Proxy Mode                  │
│  - Intercepts Qubits                                      │
│  - Measures in Guessed Bases (Collapses Quantum States)   │
│  - Forwards Modified Qubits to Bob                        │
└─────────────────────────────┬─────────────────────────────┘
                              │ Forwards Collapsed Qubits
                              ▼
                  ┌────────────────────────┐
                  │    LAPTOP B (Bob)      │
                  │     Receiver Mode      │
                  │  (Detects ~25% QBER!   │
                  │   Aborts Transmission) │
                  └────────────────────────┘
```

---

## 💻 3-Laptop Setup Instructions

### Prerequisites
- All laptops must be connected to the **same Wi-Fi network** or **LAN**.
- Start the dashboard on all laptops:
  ```bash
  streamlit run app.py
  ```

---

### Step 1: Set Up Laptop B (Receiver / Bob)
1. On **Laptop B**, go to **`🌐 Multi-Laptop File Transmission`** -> Sub-tab **`📥 Laptop B: Receiver (Bob)`**.
2. Note **Laptop B's LAN IP address** (e.g., `192.168.1.105`).
3. Set Port to `8502` and click **`▶ Start Receiver Listener`**.

---

### Step 2: Set Up Laptop C (Eavesdropper Proxy / Eve)
1. On **Laptop C (3rd Laptop)**, go to **`🌐 Multi-Laptop File Transmission`** -> Sub-tab **`🕵️ Laptop C: MITM Proxy (Eve)`**.
2. Note **Laptop C's LAN IP address** (e.g., `192.168.1.108`).
3. Set **Target Bob IP** to Laptop B's IP (`192.168.1.105`) and Target Port to `8502`.
4. Set Eve Listener Port to `8503`.
5. Click **`▶ Start Eve Proxy Listener`**.

---

### Step 3: Transmit File from Laptop A (Transmitter / Alice)
1. On **Laptop A**, go to **`🌐 Multi-Laptop File Transmission`** -> Sub-tab **`📤 Laptop A: Transmitter (Alice)`**.
2. Set **Target IP** to **Laptop C's (Eve's) IP** (`192.168.1.108`) and Target Port to `8503`.
3. Upload **ANY file** (Image, PDF, Document, ZIP, MP4, Text, etc.).
4. Click **`🚀 Transmit File via QKD ('Call Transmission')`**.

---

## 📊 Expected Outcomes

### Scenario 1: Clean Direct Transmission (Laptop A ➔ Laptop B)
- **Target IP**: Laptop B (`192.168.1.105:8502`)
- **QBER**: `~0.00%` (Safe ≤ 11%)
- **Result**: ✅ **AES-256 Key Established**. File decrypted, previewed, and downloaded on Laptop B!

### Scenario 2: Eavesdropper Interception (Laptop A ➔ Laptop C [Eve] ➔ Laptop B)
- **Target IP**: Laptop C (`192.168.1.108:8503`)
- **QBER**: `~18% - 25%` (Spikes above 11% threshold due to quantum state collapse)
- **Result**: 🚨 **KEY REJECTED & TRANSMISSION ABORTED**. Bob and Alice detect eavesdropping; file transfer is blocked! Laptop C (Eve) displays live interception metrics.
