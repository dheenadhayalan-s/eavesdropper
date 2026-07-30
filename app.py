"""
app.py — Live demo dashboard for the BB84 QKD Simulator with Eavesdropper Detection.

Run with:
    streamlit run app.py

Demo flow (recommended for judges):
  1. Set Eve OFF, hit "Run Session" a few times -> QBER stays near 0%.
  2. Turn Eve ON at 100% interception -> QBER jumps ~20-25%, key rejected live.
  3. Turn Eve ON at ~20-30% interception -> show it can slip under the naive
     fixed threshold, then flip to "Hypothesis Test" mode to catch it anyway.
  4. Show the QBER-vs-N convergence chart to prove statistical stability at scale.
"""

import time
import numpy as np
import matplotlib.pyplot as plt
import streamlit as st
import uuid

from bb84_core import run_bb84, decide_secure, hypothesis_test_decision, run_bb84_stepwise
from blockchain import AuditManager
from qiskit_circuit_demo import (
    run_bb84_qiskit, qber_shot_distribution,
    get_example_circuits, build_full_qubit_circuit
)

from qkd_network import get_local_ip_addresses, QKDNetworkListener, EveProxyListener, transmit_file_over_qkd, QBER_THRESHOLD

st.set_page_config(page_title="BB84 QKD Simulator", layout="wide")

# Initialize Audit Manager
audit_manager = AuditManager("blockchain.json")

# Inject Custom Cyberpunk Dark/Glassmorphism Styles
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

/* Main Body font and background */
html, body, [data-testid="stAppViewContainer"] {
    font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
    background-color: #0b0f19;
    color: #e2e8f0;
}

/* Titles and Headers */
h1, h2, h3, [data-testid="stHeader"] {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    letter-spacing: -0.02em;
}

/* Standardizing metrics styling */
[data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    color: #38bdf8 !important;
}

/* Code block styles */
code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Glassmorphism style for cards (expanders) */
[data-testid="stExpander"] {
    background: rgba(17, 25, 40, 0.4) !important;
    border-radius: 12px !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    backdrop-filter: blur(12px) saturate(150%) !important;
    margin-bottom: 12px !important;
    transition: all 0.3s ease;
}
[data-testid="stExpander"]:hover {
    border-color: rgba(56, 189, 248, 0.4) !important;
    box-shadow: 0 4px 20px rgba(56, 189, 248, 0.15) !important;
}

/* Style for Buttons */
div.stButton > button {
    border-radius: 8px !important;
    font-weight: 600 !important;
    transition: all 0.3s ease !important;
}
div.stButton > button:hover {
    transform: translateY(-1px) !important;
}
</style>
""", unsafe_allow_html=True)

st.title("🔐 Quantum Key Distribution Simulator")
st.caption("BB84 protocol — live eavesdropper detection & multi-laptop file transmission demo")

tab_live, tab_batch, tab_explorer, tab_qiskit, tab_net = st.tabs([
    "🔴 Live Real-Time Transmission",
    "📊 Batch Session Mode",
    "🔗 Blockchain Explorer",
    "⚛️ Qiskit Circuit Lab",
    "🌐 Multi-Laptop File Transmission",
])

# =====================================================================
# TAB 1: LIVE REAL-TIME "ALICE SPEAKS, BOB LISTENS" DEMO
# =====================================================================
with tab_live:
    st.subheader("Alice ↔ Bob — Live Qubit-by-Qubit Transmission")
    st.caption("Watch each qubit travel across the quantum channel, in order, "
               "exactly as it would in a real key-exchange session.")

    lc1, lc2, lc3, lc4 = st.columns(4)
    live_n = lc1.number_input("Qubits to send", 5, 200, 30, step=5)
    live_eve = lc2.toggle("Eve tapping the line", value=False, key="live_eve")
    live_eve_frac = lc3.slider("Eve interception %", 0.0, 1.0, 1.0, step=0.05,
                                disabled=not live_eve, key="live_eve_frac")
    live_speed = lc4.select_slider("Speed", options=["Slow", "Normal", "Fast"], value="Normal")
    live_noise = st.slider("Channel noise probability", 0.0, 0.10, 0.0, step=0.01, key="live_noise")

    delay = {"Slow": 0.6, "Normal": 0.25, "Fast": 0.05}[live_speed]

    start_live = st.button("▶ Start Live Transmission", type="primary")

    if start_live:
        st.session_state.live_session_id = f"LIVE-{uuid.uuid4().hex[:6].upper()}"
        log_box = st.container(height=350, border=True)
        progress = st.progress(0)
        stat_a, stat_b, stat_c, stat_d = st.columns(4)
        m_sent = stat_a.empty()
        m_match = stat_b.empty()
        m_key = stat_c.empty()
        m_qber = stat_d.empty()
        chart_slot = st.empty()

        sifted_a, sifted_b = [], []
        rolling_qber = []

        for step, event in enumerate(
            run_bb84_stepwise(live_n, live_eve, live_eve_frac if live_eve else 0.0,
                               live_noise, seed=None)
        ):
            basis_name = {0: "＋ (rectilinear)", 1: "✕ (diagonal)"}
            i = event["i"]

            line = f"**#{i+1}** — Alice sends bit `{event['alice_bit']}` in basis {basis_name[event['alice_basis']]}"
            if event["eve_hit"]:
                line += f"  🕵️ *Eve intercepts!* measures in {basis_name[event['eve_basis']]} → reads `{event['eve_result']}`, resends"
            if event["noise_flip"]:
                line += "  ⚡ *channel noise flips it*"
            line += f"  → Bob measures in {basis_name[event['bob_basis']]} → gets `{event['bob_result']}`"

            if event["basis_match"]:
                sifted_a.append(event["alice_bit"])
                sifted_b.append(event["bob_result"])
                line += "  ✅ **bases matched → kept for sifted key**"
            else:
                line += "  ⬜ bases differ → discarded"

            log_box.markdown(line)
            progress.progress((step + 1) / live_n)

            m_sent.metric("Qubits sent", step + 1)
            m_match.metric("Basis matches", len(sifted_a))

            if len(sifted_a) >= 4:
                arr_a, arr_b = np.array(sifted_a), np.array(sifted_b)
                q = np.mean(arr_a != arr_b)
                rolling_qber.append(q * 100)
                m_qber.metric("Running QBER", f"{q*100:.1f}%")
            else:
                m_qber.metric("Running QBER", "…")

            m_key.metric("Sifted key so far", len(sifted_a))

            if len(rolling_qber) > 1:
                fig, ax = plt.subplots(figsize=(6, 2))
                ax.plot(rolling_qber, color="crimson" if live_eve else "seagreen")
                ax.axhline(11, color="black", linestyle="--", linewidth=1)
                ax.set_ylabel("QBER (%)")
                ax.set_xlabel("as key grows")
                chart_slot.pyplot(fig)
                plt.close(fig)

            time.sleep(delay)

        st.divider()
        final_qber = (np.mean(np.array(sifted_a) != np.array(sifted_b))
                      if len(sifted_a) >= 2 else None)
        if final_qber is not None:
            secure = decide_secure(final_qber)
            session_id = st.session_state.live_session_id
            
            # Log to blockchain automatically
            audit_manager.log_simulation(
                session_id=session_id,
                key_length=len(sifted_a),
                qber=float(final_qber),
                eve_detected=not secure
            )
            # Invalidate cached in-memory chain blocks to force reload
            if "blockchain_blocks" in st.session_state:
                del st.session_state.blockchain_blocks
            
            THRESHOLD = 11.0
            qber_pct = final_qber * 100
            if secure:
                st.success(
                    f"✅ **SESSION SECURE** — QBER {qber_pct:.1f}% is below the {THRESHOLD}% threshold. "
                    f"Shared key of **{len(sifted_a)} bits** established successfully."
                )
            else:
                st.error(
                    f"🚨 **KEY AUTOMATICALLY DISCARDED** — QBER {qber_pct:.1f}% exceeds the {THRESHOLD}% "
                    f"security threshold. The channel is compromised. No key was established."
                )
                st.markdown(
                    f"> **Why?** QBER `{qber_pct:.1f}%` > threshold `{THRESHOLD}%` → "
                    f"statistically impossible without an eavesdropper. Key aborted per BB84 protocol."
                )
            st.info(f"💾 **Audit block logged to blockchain successfully!** Session ID: `{session_id}`")
        else:
            st.warning("Not enough matching bases to compute QBER — try more qubits.")

# =====================================================================
# TAB 2: ORIGINAL BATCH / STATISTICAL MODE
# =====================================================================
with tab_batch:
    st.sidebar.header("Batch Session Controls")

    n_qubits = st.sidebar.slider("Number of qubits sent", 100, 20000, 2000, step=100)
    eve_active = st.sidebar.toggle("👁️ Eve is eavesdropping", value=False)
    eve_fraction = st.sidebar.slider("Eve's interception fraction", 0.0, 1.0, 1.0, step=0.05,
                                      disabled=not eve_active)
    noise_prob = st.sidebar.slider("Channel noise probability", 0.0, 0.10, 0.01, step=0.005)
    sample_fraction = st.sidebar.slider("Fraction of sifted key sacrificed for QBER check",
                                         0.1, 0.9, 0.5, step=0.05)

    detection_mode = st.sidebar.radio(
        "Detection method",
        ["Fixed threshold (~11%)", "Statistical hypothesis test vs. noise baseline"],
    )

    run_clicked = st.sidebar.button("▶ Run Session", type="primary", use_container_width=True)

    # Session history kept across reruns for the trend chart
    if "history" not in st.session_state:
        st.session_state.history = []

    # ---------------- Baseline noise calibration (for hypothesis test mode) ----------------
    @st.cache_data
    def calibrate_baseline(noise_prob, n_qubits, sample_fraction, n_trials=40):
        """Run several Eve-free sessions to build a noise-only QBER baseline distribution."""
        qbers = []
        for i in range(n_trials):
            r = run_bb84(n_qubits, eve_active=False, eve_fraction=0.0,
                          noise_prob=noise_prob, sample_fraction=sample_fraction, seed=1000 + i)
            if r["qber"] is not None:
                qbers.append(r["qber"])
        qbers = np.array(qbers)
        return qbers.mean(), qbers.std() if qbers.std() > 0 else 1e-6


    baseline_mean, baseline_std = calibrate_baseline(noise_prob, n_qubits, sample_fraction)

    # ---------------- Run a session ----------------
    if run_clicked:
        result = run_bb84(
            n_qubits=n_qubits,
            eve_active=eve_active,
            eve_fraction=eve_fraction if eve_active else 0.0,
            noise_prob=noise_prob,
            sample_fraction=sample_fraction,
            seed=None,
        )
        st.session_state.history.append(result)
        st.session_state.last_result = result

        # Decide if secure to log eve_detected state properly
        if detection_mode.startswith("Fixed"):
            secure = decide_secure(result["qber"])
        else:
            n_sample = int(result["sifted_key_len"] * sample_fraction) if result["sifted_key_len"] else 0
            secure, z = hypothesis_test_decision(result["qber"], baseline_mean, baseline_std, n_sample)

        session_id = f"BATCH-{uuid.uuid4().hex[:6].upper()}"
        audit_manager.log_simulation(
            session_id=session_id,
            key_length=result["final_key_len"],
            qber=float(result["qber"]) if result["qber"] is not None else 0.0,
            eve_detected=not secure if secure is not None else False
        )
        st.session_state.last_session_id = session_id
        if "blockchain_blocks" in st.session_state:
            del st.session_state.blockchain_blocks

    # ---------------- Main display ----------------
    col1, col2 = st.columns([1, 1])

    if "last_result" in st.session_state:
        r = st.session_state.last_result

        with col1:
            st.subheader("Session Result")
            m1, m2, m3 = st.columns(3)
            m1.metric("Qubits sent", r["n_qubits"])
            m2.metric("Sifted key length", r["sifted_key_len"])
            m3.metric("Measured QBER", f"{r['qber']*100:.2f}%" if r["qber"] is not None else "N/A")

            if detection_mode.startswith("Fixed"):
                secure = decide_secure(r["qber"])
                z = None
            else:
                n_sample = int(r["sifted_key_len"] * sample_fraction) if r["sifted_key_len"] else 0
                secure, z = hypothesis_test_decision(r["qber"], baseline_mean, baseline_std, n_sample)

            THRESHOLD = 11.0
            qber_pct = r['qber'] * 100 if r['qber'] is not None else 0.0
            if secure:
                st.success(
                    f"✅ **CHANNEL SECURE** — QBER {qber_pct:.2f}% is below the {THRESHOLD}% threshold. "
                    f"Final key of **{r['final_key_len']} bits** established."
                )
            elif secure is False:
                st.error(
                    f"🚨 **KEY AUTOMATICALLY DISCARDED** — QBER {qber_pct:.2f}% exceeds the "
                    f"{THRESHOLD}% security threshold. Session aborted, no key established."
                )
                st.markdown(
                    f"> **Why?** QBER `{qber_pct:.2f}%` > threshold `{THRESHOLD}%` → "
                    f"eavesdropper activity detected. Key discarded per BB84 security protocol."
                )
            else:
                st.warning("⚠️ Not enough sifted bits to make a security decision.")

            if z is not None:
                st.caption(f"Hypothesis test z-score: {z:.2f}  "
                           f"(baseline noise QBER ≈ {baseline_mean*100:.2f}% ± {baseline_std*100:.2f}%)")

            if r["eve_active"]:
                st.caption(f"Eve intercepted {r['eve_intercepted_count']} of {r['n_qubits']} qubits "
                           f"({r['eve_fraction']*100:.0f}% target rate).")

            if "last_session_id" in st.session_state:
                st.info(f"💾 **Audit block logged to blockchain successfully!** Session ID: `{st.session_state.last_session_id}`")

        with col2:
            st.subheader("QBER Trend Across Runs")
            if st.session_state.history:
                fig, ax = plt.subplots()
                qbers = [h["qber"] * 100 if h["qber"] is not None else 0 for h in st.session_state.history]
                colors = ["crimson" if h["eve_active"] else "seagreen" for h in st.session_state.history]
                ax.bar(range(len(qbers)), qbers, color=colors)
                ax.axhline(11, color="black", linestyle="--", linewidth=1, label="11% fixed threshold")
                ax.set_xlabel("Session #")
                ax.set_ylabel("QBER (%)")
                ax.legend()
                ax.set_title("Green = Eve off, Red = Eve on")
                st.pyplot(fig)
    else:
        st.info("👈 Set your parameters and click **Run Session** to start the demo.")

    # ---------------- Convergence proof (scalability argument) ----------------
    st.divider()
    st.subheader("📈 Statistical Convergence — Why QBER Estimation Is Reliable at Scale")
    st.caption("Shows how the estimated QBER stabilizes as the number of qubits grows, "
               "justifying why this approach scales to real-world key sizes.")

    if st.button("Run convergence demo (no Eve)"):
        sizes = [50, 200, 1000, 5000, 20000, 50000]
        qber_estimates = []
        for s in sizes:
            r = run_bb84(s, eve_active=False, eve_fraction=0.0, noise_prob=noise_prob,
                          sample_fraction=sample_fraction, seed=42)
            qber_estimates.append((r["qber"] or 0) * 100)

        fig2, ax2 = plt.subplots()
        ax2.plot(sizes, qber_estimates, marker="o")
        ax2.set_xscale("log")
        ax2.set_xlabel("Number of qubits (log scale)")
        ax2.set_ylabel("Estimated QBER (%)")
        ax2.set_title("QBER estimate stabilizes as N grows")
        st.pyplot(fig2)

    st.divider()
    st.caption("Built on the BB84 protocol (Bennett & Brassard, 1984). "
               "Security rests on the no-cloning theorem and measurement-induced disturbance.")


# =====================================================================
# TAB 3: BLOCKCHAIN AUDIT EXPLORER & TAMPER DEMO
# =====================================================================
with tab_explorer:
    st.subheader("🔗 Quantum Audit Trail Explorer")
    st.caption("This cryptographically secure ledger records all BB84 simulator sessions. "
               "Each block references the previous hash, forming a linear chronological chain that cannot be altered retroactively.")

    # Load from disk into session_state if not present
    if "blockchain_blocks" not in st.session_state:
        audit_manager.load_audit_trail()
        st.session_state.blockchain_blocks = list(audit_manager.blockchain.chain)

    blocks = st.session_state.blockchain_blocks

    # Action buttons for verification and resetting
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 2])
    with col_btn1:
        verify_clicked = st.button("🔍 Verify Blockchain", type="primary", use_container_width=True)
    with col_btn2:
        reset_clicked = st.button("🔄 Reset & Sync Ledger", use_container_width=True)

    if verify_clicked:
        from blockchain import Blockchain
        temp_bc = Blockchain()
        temp_bc.chain = blocks
        is_valid, err_idx = temp_bc.verify_chain()
        if is_valid:
            st.success("✅ **Blockchain Verified**: The entire cryptographic audit trail is intact and completely untampered!")
        else:
            st.error(f"🚨 **Blockchain Tampered**: Integrity check failed! Block at Index **{err_idx}** has been tampered with. "
                     f"The block's current contents do not match its cryptographic signature, or the chain hash links are broken.")

    if reset_clicked:
        # Discard memory edits and reload from file
        audit_manager.load_audit_trail()
        st.session_state.blockchain_blocks = list(audit_manager.blockchain.chain)
        st.success("🔄 Blockchain database successfully reloaded from file and memory tampering cleared!")
        st.rerun()

    # Tampering Demo Section
    st.markdown("### 🛠️ Tamper Demo")
    st.caption("This tool demonstrates the tamper-detection power of blockchain. "
               "Select a block to intentionally alter its data in memory. This will invalidate the chain without recalculating hashes.")
    
    # Exclude genesis block (index 0) from tampering dropdown
    tamperable_blocks = [b for b in blocks if b.index > 0]
    if tamperable_blocks:
        options = {f"Block #{b.index} - Session: {b.audit_data.get('session_id', 'N/A')}": b.index for b in tamperable_blocks}
        selected_option = st.selectbox("Select a block to tamper:", list(options.keys()))
        selected_index = options[selected_option]
        
        # Slider to choose new tampered QBER value
        tamper_qber = st.slider("Set tampered QBER value (%):", 0.0, 1.0, 0.99, step=0.01)
        tamper_btn = st.button("⚠️ Tamper Selected Block in Memory", type="secondary")
        
        if tamper_btn:
            # Modify in memory!
            for b in st.session_state.blockchain_blocks:
                if b.index == selected_index:
                    old_qber = b.audit_data.get("qber", 0.0)
                    b.audit_data["qber"] = tamper_qber
                    st.warning(f"⚠️ **Block #{selected_index} Data Modified in Memory!**\n\n"
                               f"QBER was changed from `{old_qber*100:.2f}%` to `{tamper_qber*100:.2f}%` without updating the block hash.\n\n"
                               f"Run **Verify Blockchain** above to test the integrity check.")
                    break
    else:
        st.info("No logged simulation blocks available to tamper. Run a Batch or Live session to populate the ledger!")

    st.markdown("### 📦 Chain Blocks")
    # Display blocks in reverse order so latest block is first
    for block in reversed(blocks):
        if block.index == 0:
            header = f"🧱 Block #0 (Genesis Block)"
        else:
            header = f"🧱 Block #{block.index} [Session ID: {block.audit_data.get('session_id', 'N/A')}]"
            
        with st.expander(header):
            col_b1, col_b2 = st.columns([1, 1])
            with col_b1:
                st.markdown(f"**Index:** `{block.index}`")
                
                # Format time
                local_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))
                st.markdown(f"**Timestamp:** {local_time}")
                
                if block.index == 0:
                    st.markdown(f"**System Note:** {block.audit_data.get('message', 'N/A')}")
                else:
                    st.markdown(f"**Session ID:** `{block.audit_data.get('session_id', 'N/A')}`")
                    st.markdown(f"**Establish Key Length:** `{block.audit_data.get('key_length', 'N/A')} bits`")
                    q_val = block.audit_data.get('qber', None)
                    q_str = f"{q_val * 100:.2f}%" if q_val is not None else "N/A"
                    st.markdown(f"**QBER:** `{q_str}`")
                    
                    eve_det = block.audit_data.get('eve_detected', None)
                    eve_str = "🕵️ **Eve Detected** (QBER above threshold)" if eve_det else "✅ **Secure** (QBER within baseline)"
                    st.markdown(f"**Eve Status:** {eve_str}")
            with col_b2:
                st.markdown(f"**Previous Block Hash:**")
                st.code(block.previous_hash, language="text")
                st.markdown(f"**Current Block Hash:**")
                st.code(block.hash, language="text")
                
                # Check single block verification
                block_calc_hash = block.calculate_hash()
                if block.hash == block_calc_hash:
                    st.success("🟢 Block integrity intact (hash verified)")
                else:
                    st.error("🔴 Block modified! (computed hash mismatch)")


# =====================================================================
# TAB 4: QISKIT QUANTUM CIRCUIT LAB
# =====================================================================
with tab_qiskit:
    st.subheader("⚛️ Qiskit Quantum Circuit Lab")
    st.caption(
        "This tab runs actual quantum circuits using Qiskit + Aer — not a statistical model. "
        "Each qubit is encoded with real quantum gates (X, H) and measured via the Born rule. "
        "Perfect for showing judges the underlying quantum physics."
    )

    # ── Section 1: Circuit Gallery ──────────────────────────────────────
    st.markdown("### 🔬 Quantum Gate Circuit Gallery")
    st.caption(
        "These are the actual quantum circuits that implement BB84 encoding and measurement. "
        "Gates shown: **X** (bit-flip), **H** (Hadamard / basis switch), **Measure** (collapses qubit)."
    )

    example_circuits = get_example_circuits()
    selected_circuit_name = st.selectbox(
        "Select a circuit to inspect:",
        list(example_circuits.keys()),
        key="qiskit_circ_select"
    )
    selected_qc = example_circuits[selected_circuit_name]

    circ_col1, circ_col2 = st.columns([1, 1])
    with circ_col1:
        st.markdown(f"**Circuit:** `{selected_circuit_name}`")
        st.code(selected_qc.draw(output="text").single_string(), language="text")
    with circ_col2:
        st.markdown("**Gate Legend:**")
        st.markdown("""
| Gate | Action |
|------|--------|
| **X** | Bit-flip: |0> -> |1>, |1> -> |0> |
| **H** | Hadamard: switches Z <-> X basis |
| **Measure** | Collapses qubit to 0 or 1 (Born rule) |
| **Barrier** | Visual separator (no physical effect) |
| **Reset** | Resets qubit to |0> (Eve's resend) |
        """)
        ops = selected_qc.count_ops()
        if ops:
            st.markdown("**Gate counts in this circuit:**")
            for gate, count in ops.items():
                st.markdown(f"- `{gate}`: {count}")

    st.divider()

    # ── Section 2: QBER via Quantum Statistics ──────────────────────────
    st.markdown("### 📊 Born Rule QBER — Quantum Statistics Demo")
    st.caption(
        "Run the same-basis scenario many times (shots) using real quantum circuits. "
        "Without Eve, QBER should be ~0%. With Eve (random basis interception), "
        "quantum mechanics predicts exactly ~25% error rate — watch it emerge!"
    )

    qstat_col1, qstat_col2 = st.columns([1, 2])
    with qstat_col1:
        q_shots = st.slider("Number of shots (qubit runs)", 50, 500, 200, step=50, key="q_shots")
        q_eve   = st.toggle("Eve intercepts (random basis)", value=False, key="q_eve")
        q_efrac = st.slider("Eve fraction", 0.0, 1.0, 1.0, step=0.1,
                            disabled=not q_eve, key="q_efrac")
        run_qstat = st.button("▶ Run Quantum QBER Test", type="primary", key="run_qstat")

    with qstat_col2:
        if run_qstat:
            with st.spinner(f"Running {q_shots} real quantum circuits on Aer simulator..."):
                stats = qber_shot_distribution(
                    n_shots=q_shots,
                    eve_active=q_eve,
                    eve_fraction=q_efrac if q_eve else 0.0,
                    seed=None,
                )
            s1, s2, s3 = st.columns(3)
            s1.metric("Total Shots", stats["n_shots"])
            s2.metric("Errors (mismatches)", stats["errors"])
            s3.metric("Quantum QBER", f"{stats['qber']*100:.1f}%")

            fig, ax = plt.subplots(figsize=(5, 2.5))
            ax.bar(["Correct", "Error"],
                   [stats["correct"], stats["errors"]],
                   color=["#22c55e", "#ef4444"], width=0.4)
            ax.set_ylabel("Count")
            ax.set_title(f"Quantum Measurement Results ({q_shots} shots)")
            ax.set_facecolor("#0f172a")
            fig.patch.set_facecolor("#0f172a")
            ax.tick_params(colors="#94a3b8")
            ax.yaxis.label.set_color("#94a3b8")
            ax.title.set_color("#e2e8f0")
            for spine in ax.spines.values():
                spine.set_edgecolor("#334155")
            st.pyplot(fig)
            plt.close(fig)

            expected = 0.25 * q_efrac if q_eve else 0.0
            st.caption(
                f"Theoretical prediction: ~{expected*100:.1f}% QBER. "
                f"Observed: {stats['qber']*100:.1f}%. "
                f"{'Eve detection confirmed by quantum statistics!' if q_eve and stats['qber'] > 0.1 else 'Clean channel confirmed.'}"
            )
        else:
            st.info("Configure the settings and click **Run Quantum QBER Test** to execute real quantum circuits.")

    st.divider()

    # ── Section 3: Full BB84 session via Qiskit ──────────────────────────
    st.markdown("### 🚀 Full BB84 Session via Qiskit Circuits")
    st.caption(
        "Run a complete BB84 key exchange where every single qubit uses a real Qiskit "
        "quantum circuit. Slower than the statistical model but physically exact. "
        "Keep n_qubits small (<=50) for a fast demo."
    )

    qfull_col1, qfull_col2 = st.columns([1, 2])
    with qfull_col1:
        qf_n       = st.number_input("Number of qubits", 5, 100, 20, step=5, key="qf_n")
        qf_eve     = st.toggle("Enable Eve", value=False, key="qf_eve")
        qf_efrac   = st.slider("Eve fraction", 0.0, 1.0, 1.0, step=0.1,
                               disabled=not qf_eve, key="qf_efrac")
        qf_sample  = st.slider("QBER sample fraction", 0.1, 0.9, 0.5, step=0.1, key="qf_sample")
        run_qfull  = st.button("▶ Run Full Qiskit BB84", type="primary", key="run_qfull")

    with qfull_col2:
        if run_qfull:
            with st.spinner(f"Executing {qf_n} quantum circuits on Aer... (this may take a few seconds)"):
                qf_result = run_bb84_qiskit(
                    n_qubits=int(qf_n),
                    eve_active=qf_eve,
                    eve_fraction=qf_efrac if qf_eve else 0.0,
                    sample_fraction=qf_sample,
                    seed=None,
                )

            r1, r2, r3 = st.columns(3)
            r1.metric("Qubits sent", qf_result["n_qubits"])
            r2.metric("Sifted key length", qf_result["sifted_key_len"])
            r3.metric("Final key length", qf_result["final_key_len"])

            q2, q3 = st.columns(2)
            qber_val = qf_result["qber"]
            q2.metric("Measured QBER", f"{qber_val*100:.2f}%" if qber_val is not None else "N/A")
            q3.metric("Eve hits", qf_result["eve_intercepted_count"])

            THRESHOLD = 11.0
            qber_pct = qber_val * 100 if qber_val is not None else None

            if qber_pct is None:
                # No QBER could be measured at all (zero sifted bits)
                st.warning("⚠️ **No sifted key produced** — too few qubits had matching bases. "
                           "Increase the qubit count and try again.")
            elif qber_pct > THRESHOLD:
                # QBER above threshold — auto-discard regardless of decide_secure result
                st.error(
                    f"🚨 **KEY AUTOMATICALLY DISCARDED** — QBER {qber_pct:.2f}% exceeds the "
                    f"{THRESHOLD}% security threshold. Qiskit quantum circuits confirmed eavesdropper presence."
                )
                st.markdown(
                    f"> **Quantum proof:** QBER `{qber_pct:.2f}%` > threshold `{THRESHOLD}%` → "
                    f"Eve's measurement collapsed qubit states, introducing detectable disturbance. "
                    f"Key discarded per BB84 no-cloning security protocol."
                )
            else:
                # QBER is fine — secure key established
                st.success(
                    f"✅ **QISKIT SESSION SECURE** — QBER {qber_pct:.2f}% is below the {THRESHOLD}% threshold. "
                    f"Key of **{qf_result['final_key_len']} bits** established via real quantum circuits!"
                )

            st.markdown("**Example circuit for this session (bit=1, X-basis, Eve present/absent):**")
            demo_qc = build_full_qubit_circuit(
                alice_bit=1, alice_basis=1, bob_basis=1,
                eve_basis=0 if qf_eve else None
            )
            st.code(demo_qc.draw(output="text").single_string(), language="text")
        else:
            st.info("Configure the settings and click **Run Full Qiskit BB84** to simulate with real quantum circuits.")

    st.divider()
    st.caption(
        "Powered by **Qiskit** (IBM) and **Qiskit Aer** (high-performance quantum circuit simulator). "
        "Gates: X (bit-flip), H (Hadamard/basis switch), Measure (Born rule collapse), "
        "Reset (Eve resend modelling). "
        "Security rooted in quantum no-cloning theorem and measurement-induced disturbance."
    )


# =====================================================================
# TAB 5: MULTI-LAPTOP NETWORK FILE TRANSMISSION ("CALL TRANSMISSION")
# =====================================================================
with tab_net:
    st.subheader("🌐 Multi-Laptop Network File Transmission & Eve MITM Interceptor")
    st.caption(
        "Demonstrate BB84 QKD key exchange & secure AES-256 file transmission across **2 or 3 separate laptops** "
        "over Wi-Fi / LAN. Transmit ANY file (Images, PDFs, Text, ZIP, Docs, Video, etc.)."
    )

    local_ips = get_local_ip_addresses()
    ip_badges = " ".join([f"`{ip}`" for ip in local_ips])
    
    st.info(
        f"📡 **Your Machine Local LAN IP(s):** {ip_badges}\n\n"
        f"**Multi-Laptop Demonstration Setups:**\n"
        f"- **2-Laptop Setup (Alice ↔ Bob):** Laptop B starts Listener on port `8502`. Laptop A connects directly to Laptop B's IP on port `8502`.\n"
        f"- **3-Laptop Eavesdropper Setup (Alice ↔ Eve Proxy ↔ Bob):**\n"
        f"  1. **Laptop B (Bob / Receiver):** Starts Receiver Listener on port `8502`.\n"
        f"  2. **Laptop C (Eve / MITM Proxy):** Starts Eve Proxy Listener on port `8503` targeting Laptop B's IP:8502.\n"
        f"  3. **Laptop A (Alice / Transmitter):** Connects to Laptop C's IP on port `8503`. Eve intercepts qubits, causing ~25% QBER! Transmission is aborted!"
    )

    sub_bob, sub_alice, sub_eve = st.tabs([
        "📥 Laptop B: Receiver (Bob)",
        "📤 Laptop A: Transmitter (Alice)",
        "🕵️ Laptop C: MITM Proxy (Eve)",
    ])

    # ------------------ SUB-TAB 1: RECEIVER (BOB) ------------------
    with sub_bob:
        st.markdown("### 📥 Laptop B: Receiver Mode (Bob)")
        st.caption("Listens on TCP port for incoming QKD key exchanges & encrypted file payloads.")

        b_col1, b_col2 = st.columns([1, 1])
        with b_col1:
            port_input = st.number_input("Listener Port", value=8502, step=1, key="net_port")
            eve_listener = st.toggle("🕵️ Simulate Local Eve Interception on Bob Channel", value=False, key="net_eve_listen")
            eve_frac_listen = st.slider("Eve Interception Rate", 0.0, 1.0, 1.0, step=0.1, disabled=not eve_listener, key="net_eve_frac")

            # Initialize network listener in session_state if missing
            if "network_listener" not in st.session_state:
                st.session_state.network_listener = QKDNetworkListener(host="0.0.0.0", port=port_input)

            listener: QKDNetworkListener = st.session_state.network_listener
            listener.port = port_input
            listener.eve_active = eve_listener
            listener.eve_frac = eve_frac_listen

            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                if st.button("▶ Start Receiver Listener", type="primary" if not listener.is_running else "secondary", key="btn_start_listen", use_container_width=True):
                    listener.start()
                    st.rerun()
            with btn_col2:
                if st.button("🛑 Stop Listener", key="btn_stop_listen", use_container_width=True):
                    listener.stop()
                    st.rerun()

            if listener.is_running:
                st.success(f"🟢 Receiver Listener ACTIVE on `0.0.0.0:{listener.port}` (Share IP `{local_ips[0]}`)")
            else:
                st.warning("🔴 Receiver Listener is currently STOPPED.")

            with st.expander("📋 Bob's Real-Time Log Console", expanded=True):
                if listener.logs:
                    st.code("\n".join(listener.logs[-15:]), language="text")
                else:
                    st.caption("No log events yet. Start listener and initiate transmission!")

        with b_col2:
            st.markdown("#### 📦 Received Files Workspace")
            if listener.last_received_file:
                rf = listener.last_received_file
                st.success(f"🎉 **Received & Decrypted File:** `{rf['filename']}`")
                
                f_col1, f_col2 = st.columns(2)
                f_col1.metric("File Size", f"{rf['size'] / 1024:.2f} KB" if rf['size'] > 1024 else f"{rf['size']} Bytes")
                f_col2.metric("QKD QBER", f"{rf['qber']*100:.2f}%")

                st.caption(f"Session ID: `{rf['session_id']}` | Status: {rf['status_msg']}")

                file_bytes = rf["data"]
                fname = rf["filename"]
                mime = rf.get("mime_type", "application/octet-stream")

                st.download_button(
                    label=f"💾 Download Received File ({fname})",
                    data=file_bytes,
                    file_name=fname,
                    mime=mime,
                    type="primary",
                    key="dl_received_file",
                    use_container_width=True
                )

                ext = fname.split(".")[-1].lower() if "." in fname else ""
                if ext in ["png", "jpg", "jpeg", "gif", "webp", "svg"]:
                    st.image(file_bytes, caption=f"Preview: {fname}", use_container_width=True)
                elif ext in ["txt", "py", "json", "csv", "md", "log", "html", "css", "js"]:
                    try:
                        text_str = file_bytes.decode("utf-8")
                        st.code(text_str[:2000] + ("\n... [truncated]" if len(text_str) > 2000 else ""), language=ext if ext != "txt" else "text")
                    except Exception:
                        pass
            else:
                st.info("No files received yet. Files transmitted by Alice will appear here after QKD key exchange!")

    # ------------------ SUB-TAB 2: TRANSMITTER (ALICE) ------------------
    with sub_alice:
        st.markdown("### 📤 Laptop A: Transmitter Mode (Alice)")
        st.caption("Initiates QKD session with target IP (Bob or Eve Proxy), encrypts file, and transmits payload.")

        a_col1, a_col2 = st.columns([1, 1])
        with a_col1:
            target_ip = st.text_input("Target IP (Bob's IP or Eve's Proxy IP)", value=local_ips[0], key="net_target_ip")
            target_port = st.number_input("Target Port (8502 for Bob, 8503 for Eve)", value=8502, step=1, key="net_target_port")

            uploaded_file = st.file_uploader(
                "📁 Select ANY file to transmit across laptops:",
                type=None,
                key="net_file_uploader",
                help="Supports any file type: Images, PDFs, Text, ZIP, MP4, Audio, Docs, Executables, etc."
            )

            n_qubits_net = st.slider("QKD Qubits for Key Exchange", 100, 2000, 400, step=100, key="net_n_qubits")
            sample_frac_net = st.slider("QBER Sample Check Fraction", 0.1, 0.9, 0.5, step=0.1, key="net_sample_frac")

            st.markdown("---")
            eve_alice_toggle = st.toggle("🕵️ Simulate Eve Interception on Transmission Channel", value=False, key="net_alice_eve_toggle")
            eve_alice_frac = st.slider("Eve Interception Rate", 0.1, 1.0, 1.0, step=0.1, disabled=not eve_alice_toggle, key="net_alice_eve_frac")

            btn_transmit = st.button("🚀 Transmit File via QKD ('Call Transmission')", type="primary", use_container_width=True, key="btn_transmit_net")

        with a_col2:
            st.markdown("#### 📡 Transmission Output Console")
            if btn_transmit:
                if uploaded_file is None:
                    st.error("⚠️ Please select/upload a file first!")
                else:
                    file_bytes = uploaded_file.getvalue()
                    file_name = uploaded_file.name
                    mime_type = uploaded_file.type or "application/octet-stream"

                    st.markdown(f"**Starting transmission for file:** `{file_name}` ({len(file_bytes)} bytes)...")
                    status_box = st.empty()
                    log_lines = []

                    def update_status(msg):
                        log_lines.append(msg)
                        status_box.code("\n".join(log_lines[-8:]), language="text")

                    with st.spinner("Executing QKD protocol over network socket..."):
                        res = transmit_file_over_qkd(
                            target_ip=target_ip,
                            target_port=int(target_port),
                            file_name=file_name,
                            file_bytes=file_bytes,
                            mime_type=mime_type,
                            n_qubits=n_qubits_net,
                            eve_active=eve_alice_toggle,
                            eve_frac=eve_alice_frac,
                            sample_fraction=sample_frac_net,
                            status_callback=update_status,
                        )

                    if res.get("success"):
                        st.success(
                            f"🎉 **TRANSMISSION SUCCESSFUL!**\n\n"
                            f"- File `{res['file_name']}` ({res['file_size']} bytes) transmitted securely!\n"
                            f"- **Measured QBER:** `{res['qber_pct']:.2f}%` (Below {QBER_THRESHOLD*100:.0f}% threshold)\n"
                            f"- **AES-256 Key Established:** `{res['final_key_len']} bits`\n"
                            f"- **Session ID:** `{res['session_id']}`"
                        )
                    else:
                        is_sec = res.get("is_secure", None)
                        qber_val = res.get("qber_pct", None)

                        if is_sec is False and qber_val is not None:
                            st.error(
                                f"🚨 **QKD TRANSMISSION BLOCKED! (Eavesdropper Detected)**\n\n"
                                f"- **Measured QBER:** `{qber_val:.2f}%` (Exceeds {QBER_THRESHOLD*100:.0f}% threshold)\n"
                                f"- **Security Decision:** QKD key rejected due to quantum measurement disturbance!\n"
                                f"- **Details:** {res.get('error', 'Eavesdropper detected on quantum channel.')}"
                            )
                        else:
                            st.error(
                                f"🔌 **NETWORK CONNECTION FAILED**\n\n"
                                f"- **Reason:** {res.get('error', 'Connection timed out or refused.')}\n"
                                f"- **Troubleshooting Check:**\n"
                                f"  1. Is the Receiver Listener started on `{target_ip}:{target_port}`?\n"
                                f"  2. For **Bob direct connection**, use Port `8502`.\n"
                                f"  3. For **Eve 3-Laptop Proxy**, click **▶ Start Eve Proxy Listener** on Laptop C (Port `8503`) first.\n"
                                f"  4. Check if both laptops are on the same Wi-Fi / LAN network."
                            )
            else:
                st.info("Select target IP & file, then click **Transmit File via QKD** to begin.")

    # ------------------ SUB-TAB 3: MITM EAVESDROPPER PROXY (EVE) ------------------
    with sub_eve:
        st.markdown("### 🕵️ Laptop C: Man-In-The-Middle Proxy Mode (Eve)")
        st.caption("Runs on Laptop 3. Intercepts quantum qubits sent by Alice, measures in guessed bases, and forwards collapsed states to Bob.")

        e_col1, e_col2 = st.columns([1, 1])
        with e_col1:
            eve_port_input = st.number_input("Eve Listener Port (Alice connects here)", value=8503, step=1, key="eve_proxy_port")
            target_bob_ip = st.text_input("Target Bob's Laptop IP", value=local_ips[0], key="eve_target_bob_ip")
            target_bob_port = st.number_input("Target Bob's Port", value=8502, step=1, key="eve_target_bob_port")
            eve_frac_proxy = st.slider("Eve Interception Fraction", 0.0, 1.0, 1.0, step=0.1, key="eve_proxy_frac")

            # Initialize Eve Proxy Listener in session_state if missing
            if "eve_proxy" not in st.session_state:
                st.session_state.eve_proxy = EveProxyListener(
                    host="0.0.0.0",
                    port=eve_port_input,
                    target_bob_ip=target_bob_ip,
                    target_bob_port=target_bob_port,
                    eve_frac=eve_frac_proxy,
                )

            eve_proxy: EveProxyListener = st.session_state.eve_proxy
            eve_proxy.port = eve_port_input
            eve_proxy.target_bob_ip = target_bob_ip
            eve_proxy.target_bob_port = target_bob_port
            eve_proxy.eve_frac = eve_frac_proxy

            ebtn_col1, ebtn_col2 = st.columns(2)
            with ebtn_col1:
                if st.button("▶ Start Eve Proxy Listener", type="primary" if not eve_proxy.is_running else "secondary", key="btn_start_eve_proxy", use_container_width=True):
                    eve_proxy.start()
                    st.rerun()
            with ebtn_col2:
                if st.button("🛑 Stop Eve Proxy", key="btn_stop_eve_proxy", use_container_width=True):
                    eve_proxy.stop()
                    st.rerun()

            if eve_proxy.is_running:
                st.success(f"🟢 Eve MITM Proxy ACTIVE on `0.0.0.0:{eve_proxy.port}` -> Forwarding to Bob at `{target_bob_ip}:{target_bob_port}`")
                st.info(f"💡 **Alice (Laptop A)** should enter Eve's IP (`{local_ips[0]}`) and Port `{eve_proxy.port}` as the target IP/Port!")
            else:
                st.warning("🔴 Eve MITM Proxy is currently STOPPED.")

            with st.expander("📋 Eve's Real-Time Interception Log", expanded=True):
                if eve_proxy.logs:
                    st.code("\n".join(eve_proxy.logs[-15:]), language="text")
                else:
                    st.caption("No proxy events yet. Start Eve Proxy and have Alice transmit to Eve's IP/port.")

        with e_col2:
            st.markdown("#### 📊 Intercepted Sessions Dashboard")
            if eve_proxy.interceptions_history:
                for idx, item in enumerate(reversed(eve_proxy.interceptions_history)):
                    with st.expander(f"🕵️ Session #{len(eve_proxy.interceptions_history) - idx}: `{item['session_id']}`", expanded=True):
                        st.markdown(f"**Target File:** `{item.get('filename', 'N/A')}`")
                        st.markdown(f"**Total Qubits Intercepted:** `{item['n_qubits']}`")
                        st.markdown(f"**Eve Hits:** `{item['eve_hits']}`")
                        st.markdown(f"**QBER Induced on Bob:** `{item['qber_pct']:.2f}%`")
                        if item['blocked']:
                            st.error("🚨 **Transmission Blocked!** Bob detected high QBER and rejected key.")
                        else:
                            st.success("✅ Transmission Succeeded (Eve went unnoticed).")
            else:
                st.info("No intercepted sessions yet. Run a transmission from Alice targeting Eve's Proxy port (`8503`)!")




