"""
qkd_network.py
Multi-Laptop Network QKD & Secure File Transmission Engine for EaveGuard.

Enables secure end-to-end file transmission across different laptops/devices over LAN/Wi-Fi:
1. Alice (Transmitter) and Bob (Receiver) establish network socket connection.
2. QKD (BB84 protocol) takes place over the network with optional Eve (MITM proxy).
3. Public basis sifting & QBER check are performed.
4. If QBER <= 11%: Establish 256-bit symmetric key derived from quantum key.
5. Encrypt ANY file (images, PDFs, documents, zips, text, binary) with QKD key.
6. Transmit encrypted payload over network socket; Bob decrypts, verifies, and previews/saves file.
"""

import socket
import threading
import json
import time
import hashlib
import hmac
import os
import base64
import numpy as np
from typing import Dict, Any, Tuple, Optional, Callable
from blockchain import AuditManager

# Standard baseline threshold for QBER
QBER_THRESHOLD = 0.11

# Standard 6-Stage Transmission Security Pipeline
PIPELINE_STEPS = [
    {"id": 1, "key": "connect_init", "title": "Socket & QKD Init", "icon": "🔌", "desc": "Establish connection & generate qubit states"},
    {"id": 2, "key": "sift_measure", "title": "Qubit Sifting & Basis Match", "icon": "⚛️", "desc": "Measure qubits & sift matching bases"},
    {"id": 3, "key": "qber_audit", "title": "QBER & Eavesdropper Audit", "icon": "🔍", "desc": "Compare bit samples & verify ≤11% threshold"},
    {"id": 4, "key": "key_encrypt", "title": "AES-256 Key & Encryption", "icon": "🔒", "desc": "Derive symmetric key & encrypt file payload"},
    {"id": 5, "key": "transmit_payload", "title": "Encrypted Payload Streaming", "icon": "🚀", "desc": "Transmit encrypted payload over network"},
    {"id": 6, "key": "decrypt_verify", "title": "Decryption & Integrity Check", "icon": "🔓", "desc": "Verify HMAC tag & decrypt received payload"},
]


def init_pipeline_state(session_id: str = "") -> Dict[str, Any]:
    """Initialize a fresh 6-step pipeline tracking state dictionary."""
    return {
        "session_id": session_id,
        "current_step": 0,
        "overall_status": "IDLE",  # IDLE, RUNNING, SUCCESS, ABORTED, FAILED
        "steps": {
            s["id"]: {
                "id": s["id"],
                "key": s["key"],
                "title": s["title"],
                "icon": s["icon"],
                "desc": s["desc"],
                "status": "PENDING",  # PENDING, IN_PROGRESS, COMPLETED, ABORTED, FAILED
                "detail": "",
            }
            for s in PIPELINE_STEPS
        },
    }



def get_local_ip_addresses():
    """Detect local IP addresses on all active network interfaces."""
    ip_list = []
    try:
        # Connect to an external IP to find preferred route IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        primary_ip = s.getsockname()[0]
        s.close()
        ip_list.append(primary_ip)
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip not in ip_list and not ip.startswith("127."):
                ip_list.append(ip)
    except Exception:
        pass

    if not ip_list:
        ip_list = ["127.0.0.1"]
    return ip_list


# =====================================================================
# ZERO-DEPENDENCY AUTHENTICATED AES-CTR / HMAC STREAM CIPHER
# =====================================================================
def derive_aes_key(sifted_bits: list) -> bytes:
    """Derive a 256-bit secret key from sifted bits using SHA-256."""
    bit_string = "".join(str(b) for b in sifted_bits)
    return hashlib.sha256(bit_string.encode("utf-8")).digest()


def _keystream_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Generate 32-byte counter keystream block using HMAC-SHA256."""
    ctr_bytes = counter.to_bytes(8, byteorder="big")
    return hmac.new(key, nonce + ctr_bytes, hashlib.sha256).digest()


def encrypt_file_data(file_bytes: bytes, key: bytes) -> Dict[str, str]:
    """
    Encrypt file data with 256-bit key using HMAC-SHA256 CTR keystream & MAC tag.
    Returns dictionary with base64 encoded ciphertext, nonce, and hmac tag.
    """
    nonce = os.urandom(16)
    cipher_chunks = []
    block_size = 32
    
    for i in range(0, len(file_bytes), block_size):
        chunk = file_bytes[i:i + block_size]
        counter = i // block_size
        ks = _keystream_block(key, nonce, counter)
        xor_chunk = bytes(a ^ b for a, b in zip(chunk, ks[:len(chunk)]))
        cipher_chunks.append(xor_chunk)
        
    ciphertext = b"".join(cipher_chunks)
    # Compute HMAC authentication tag over nonce + ciphertext
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).hexdigest()

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "hmac_tag": tag,
        "original_size": len(file_bytes),
    }


def decrypt_file_data(payload: Dict[str, str], key: bytes) -> Tuple[bool, bytes, str]:
    """
    Decrypt encrypted file payload using 256-bit key.
    Returns (success, decrypted_bytes, status_message).
    """
    try:
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        expected_tag = payload["hmac_tag"]

        # Verify HMAC tag first (encrypt-then-mac)
        calc_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc_tag, expected_tag):
            return False, b"", "🚨 HMAC Verification Failed! Data payload tampered or key mismatch."

        block_size = 32
        plain_chunks = []
        for i in range(0, len(ciphertext), block_size):
            chunk = ciphertext[i:i + block_size]
            counter = i // block_size
            ks = _keystream_block(key, nonce, counter)
            xor_chunk = bytes(a ^ b for a, b in zip(chunk, ks[:len(chunk)]))
            plain_chunks.append(xor_chunk)

        decrypted = b"".join(plain_chunks)
        return True, decrypted, "✅ Decryption & Integrity Verification Successful!"
    except Exception as e:
        return False, b"", f"🚨 Decryption error: {str(e)}"


# =====================================================================
# MULTI-LAPTOP QKD & FILE TRANSMISSION SOCKET SERVER & CLIENT
# =====================================================================
class QKDNetworkListener:
    """
    Bob (Receiver) Listener node.
    Runs on Bob's laptop, listening for Alice's incoming QKD & File transmission requests.
    """
    def __init__(self, host: str = "0.0.0.0", port: int = 8502, eve_active: bool = False, eve_frac: float = 1.0):
        self.host = host
        self.port = port
        self.eve_active = eve_active
        self.eve_frac = eve_frac
        self.server_socket: Optional[socket.socket] = None
        self.is_running = False
        self.last_received_file: Optional[Dict[str, Any]] = None
        self.received_files: list = []
        self.last_qkd_session: Optional[Dict[str, Any]] = None
        self.logs: list = []
        self._thread: Optional[threading.Thread] = None
        self.audit_manager = AuditManager("blockchain.json")
        self._active_pipeline_state: Dict[str, Any] = init_pipeline_state()

    @property
    def active_pipeline_state(self) -> Dict[str, Any]:
        if not hasattr(self, "_active_pipeline_state") or self._active_pipeline_state is None:
            self._active_pipeline_state = init_pipeline_state()
        return self._active_pipeline_state

    @active_pipeline_state.setter
    def active_pipeline_state(self, val: Dict[str, Any]):
        self._active_pipeline_state = val

    def update_pipeline_step(self, step_id: int, status: str, detail: str = ""):
        """Update active pipeline state step status for real-time visual progress."""
        state = self.active_pipeline_state
        state["current_step"] = step_id
        if step_id in state["steps"]:
            state["steps"][step_id]["status"] = status
            if detail:
                state["steps"][step_id]["detail"] = detail
        if status in ["ABORTED", "FAILED"]:
            state["overall_status"] = status
        elif step_id == 6 and status == "COMPLETED":
            state["overall_status"] = "SUCCESS"
        elif status == "IN_PROGRESS":
            state["overall_status"] = "RUNNING"

    def log(self, msg: str):

        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {msg}"
        self.logs.append(formatted)
        try:
            print(formatted)
        except UnicodeEncodeError:
            print(formatted.encode('ascii', errors='replace').decode('ascii'))

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.logs.clear()
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()
        self.log(f"🟢 Receiver Listener started on {self.host}:{self.port}")

    def stop(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.log("🛑 Receiver Listener stopped.")

    def _run_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
        except Exception as e:
            self.log(f"🚨 Socket bind failed: {e}")
            self.is_running = False
            return

        while self.is_running:
            try:
                conn, addr = self.server_socket.accept()
                conn.settimeout(60.0)
                self.log(f"🤝 Connected to Transmitter (Alice) at {addr[0]}:{addr[1]}")
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    self.log(f"Socket accept error: {e}")
                break

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        rng = np.random.default_rng()
        try:
            # 1. Receive Session Init payload
            raw_data = self._recv_msg(conn)
            if not raw_data:
                return
            msg = json.loads(raw_data.decode("utf-8"))

            if msg.get("type") != "QKD_INIT":
                self.log(f"Unexpected message type: {msg.get('type')}")
                conn.close()
                return

            session_id = msg["session_id"]
            n_qubits = msg["n_qubits"]
            alice_bases_sent = msg.get("alice_bases")
            alice_bits_sent = msg.get("alice_bits")
            file_meta = msg.get("file_metadata")

            self.active_pipeline_state = init_pipeline_state(session_id)
            self.update_pipeline_step(1, "COMPLETED", f"Connected link for `{file_meta['filename']}` ({file_meta['size']}B)")
            self.update_pipeline_step(2, "IN_PROGRESS", f"Measuring {n_qubits} qubits in random bases...")

            self.log(f"⚡ Starting QKD session `{session_id}` with {n_qubits} qubits for file: `{file_meta['filename']}`")

            # 2. Bob measures qubits in his own random bases
            bob_bases = rng.integers(0, 2, size=n_qubits).tolist()

            # Eve interception simulation on channel if Eve active on Bob's listener or in protocol
            transmitted_bits = list(alice_bits_sent)
            transmitted_bases = list(alice_bases_sent)
            eve_intercepted_count = 0

            if self.eve_active:
                self.log(f"🕵️ Eavesdropper (Eve) tapping quantum channel (Target rate: {self.eve_frac*100:.0f}%)")
                for i in range(n_qubits):
                    if rng.random() < self.eve_frac:
                        eve_intercepted_count += 1
                        eve_basis = int(rng.integers(0, 2))
                        # Eve measures in her basis
                        if eve_basis == transmitted_bases[i]:
                            eve_result = transmitted_bits[i]
                        else:
                            eve_result = int(rng.integers(0, 2))
                        # Eve resends in her basis
                        transmitted_bits[i] = eve_result
                        transmitted_bases[i] = eve_basis

            # Bob measurement result based on transmitted state & Bob basis
            bob_results = []
            for i in range(n_qubits):
                if bob_bases[i] == transmitted_bases[i]:
                    bob_results.append(transmitted_bits[i])
                else:
                    bob_results.append(int(rng.integers(0, 2)))

            # Send Bob's bases back to Alice
            self._send_msg(conn, json.dumps({
                "type": "BOB_MEASURED",
                "bob_bases": bob_bases,
                "bob_results": bob_results,
            }).encode("utf-8"))

            self.update_pipeline_step(2, "COMPLETED", f"Measured {n_qubits} qubits. Sifting matching bases...")
            self.update_pipeline_step(3, "IN_PROGRESS", "Performing public QBER bit-sample comparison...")

            # 3. Receive Basis Sifting & Public QBER check response from Alice
            sift_data_raw = self._recv_msg(conn)
            if not sift_data_raw:
                self.update_pipeline_step(3, "FAILED", "Disconnected during basis sifting")
                return
            sift_msg = json.loads(sift_data_raw.decode("utf-8"))

            matching_indices = sift_msg["matching_indices"]
            sample_indices = sift_msg["sample_indices"]
            alice_sample_bits = sift_msg["alice_sample_bits"]

            # Perform basis sifting on Bob's end
            sifted_bob = [bob_results[idx] for idx in matching_indices]
            sifted_alice_ref = [alice_bits_sent[idx] for idx in matching_indices]

            # Calculate QBER on sample
            mismatches = 0
            for idx_pos, sample_idx in enumerate(sample_indices):
                bob_bit = bob_results[sample_idx]
                alice_bit = alice_sample_bits[idx_pos]
                if bob_bit != alice_bit:
                    mismatches += 1

            n_sample = len(sample_indices)
            qber = (mismatches / n_sample) if n_sample > 0 else 0.0
            is_secure = qber <= QBER_THRESHOLD

            self.log(f"📊 Sifting Complete — Sifted Key: {len(sifted_bob)} bits | Sample QBER: {qber*100:.2f}%")

            # Final Key extraction (excluding sample bits)
            sample_set = set(sample_indices)
            final_key_bits_bob = [
                bob_results[idx] for idx in matching_indices if idx not in sample_set
            ]

            qkd_summary = {
                "session_id": session_id,
                "n_qubits": n_qubits,
                "sifted_key_len": len(sifted_bob),
                "final_key_len": len(final_key_bits_bob),
                "qber": qber,
                "qber_pct": qber * 100,
                "is_secure": is_secure,
                "eve_active": self.eve_active,
                "eve_intercepted_count": eve_intercepted_count,
                "timestamp": time.time(),
            }
            self.last_qkd_session = qkd_summary

            # Log block to Blockchain Audit Trail
            self.audit_manager.log_simulation(
                session_id=session_id,
                key_length=len(final_key_bits_bob),
                qber=qber,
                eve_detected=not is_secure,
            )

            # Send Decision back to Alice
            self._send_msg(conn, json.dumps({
                "type": "QKD_RESULT",
                "is_secure": is_secure,
                "qber": qber,
                "qber_pct": qber * 100,
            }).encode("utf-8"))

            if not is_secure:
                self.update_pipeline_step(3, "ABORTED", f"🚨 Eavesdropper detected! QBER {qber*100:.2f}% > 11% threshold.")
                self.log(f"🚨 QKD KEY REJECTED! QBER {qber*100:.2f}% > {QBER_THRESHOLD*100:.0f}% threshold. Eavesdropper detected! Aborting transmission.")
                conn.close()
                return

            self.update_pipeline_step(3, "COMPLETED", f"✅ QBER {qber*100:.2f}% safe (≤11% threshold)")
            self.update_pipeline_step(4, "IN_PROGRESS", f"Deriving 256-bit AES key from {len(final_key_bits_bob)} secret bits...")

            # Print first 10 bits of the final key for debugging key consistency across laptops
            key_preview_bob = "".join(str(b) for b in final_key_bits_bob[:10])
            self.log(f"🔑 [DEBUG] Bob's Final Key (first 10 bits): {key_preview_bob} (len: {len(final_key_bits_bob)})")

            self.log(f"✅ QKD KEY ESTABLISHED SECURELY! Key length: {len(final_key_bits_bob)} bits. Waiting for encrypted file payload...")

            self.update_pipeline_step(4, "COMPLETED", f"Derived 256-bit AES key from QKD secret key")
            self.update_pipeline_step(5, "IN_PROGRESS", "Receiving AES-256 CTR + HMAC encrypted payload...")

            # 4. Receive Encrypted File Payload
            file_payload_raw = self._recv_msg(conn)
            if not file_payload_raw:
                self.update_pipeline_step(5, "FAILED", "Failed to receive encrypted file payload")
                return
            file_payload = json.loads(file_payload_raw.decode("utf-8"))

            self.update_pipeline_step(5, "COMPLETED", "Encrypted payload received over socket")
            self.update_pipeline_step(6, "IN_PROGRESS", "Authenticating HMAC tag & decrypting file...")

            # Derive AES key from Bob's secret key bits
            aes_key = derive_aes_key(final_key_bits_bob)

            # Decrypt file payload
            success, file_bytes, dec_msg = decrypt_file_data(file_payload["encrypted_payload"], aes_key)

            if success:
                self.update_pipeline_step(6, "COMPLETED", f"File `{file_meta['filename']}` verified & decrypted!")
                self.log(f"🎉 FILE RECEIVED & DECRYPTED SECURELY! Filename: `{file_meta['filename']}` ({file_meta['size']} bytes)")
                received_entry = {
                    "filename": file_meta["filename"],
                    "size": file_meta["size"],
                    "mime_type": file_meta.get("mime_type", "application/octet-stream"),
                    "data": file_bytes,
                    "session_id": session_id,
                    "qber": qber,
                    "decrypted_at": time.time(),
                    "status_msg": dec_msg,
                }
                self.last_received_file = received_entry
                self.received_files.append(received_entry)
                # Send ACK to Alice
                self._send_msg(conn, json.dumps({"type": "FILE_RECEIVED", "status": "SUCCESS"}).encode("utf-8"))
            else:
                self.update_pipeline_step(6, "FAILED", f"HMAC authentication failed: {dec_msg}")
                self.log(f"🚨 File decryption failed: {dec_msg}")
                self._send_msg(conn, json.dumps({"type": "FILE_RECEIVED", "status": "DECRYPTION_FAILED"}).encode("utf-8"))

        except Exception as e:
            self.log(f"🚨 Error in socket handler: {e}")
        finally:
            conn.close()

    def _send_msg(self, conn: socket.socket, data: bytes):
        length = len(data)
        conn.sendall(length.to_bytes(4, byteorder="big") + data)

    def _recv_msg(self, conn: socket.socket) -> Optional[bytes]:
        try:
            header = b""
            while len(header) < 4:
                chunk = conn.recv(4 - len(header))
                if not chunk:
                    return None
                header += chunk
            length = int.from_bytes(header, byteorder="big")
            chunks = []
            bytes_recvd = 0
            while bytes_recvd < length:
                chunk = conn.recv(min(length - bytes_recvd, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_recvd += len(chunk)
            return b"".join(chunks)
        except Exception:
            return None


def transmit_file_over_qkd(
    target_ip: str,
    target_port: int,
    file_name: str,
    file_bytes: bytes,
    mime_type: str = "application/octet-stream",
    n_qubits: int = 500,
    eve_active: bool = False,
    eve_frac: float = 1.0,
    sample_fraction: float = 0.5,
    status_callback: Optional[Callable[[str], None]] = None,
    pipeline_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """
    Sender (Alice) function.
    Connects to Bob's IP/port, executes QKD protocol, encrypts file, and transmits payload.
    """
    session_id = f"NET-{os.urandom(4).hex().upper()}"
    pipeline_state = init_pipeline_state(session_id)

    def update_step(step_id: int, status: str, detail: str = ""):
        pipeline_state["current_step"] = step_id
        if step_id in pipeline_state["steps"]:
            pipeline_state["steps"][step_id]["status"] = status
            if detail:
                pipeline_state["steps"][step_id]["detail"] = detail
        if status in ["ABORTED", "FAILED"]:
            pipeline_state["overall_status"] = status
        elif step_id == 6 and status == "COMPLETED":
            pipeline_state["overall_status"] = "SUCCESS"
        elif status == "IN_PROGRESS":
            pipeline_state["overall_status"] = "RUNNING"
        if pipeline_callback:
            pipeline_callback(pipeline_state)

    def log(msg: str):
        if status_callback:
            status_callback(msg)
        try:
            print(f"[ALICE] {msg}")
        except UnicodeEncodeError:
            print(f"[ALICE] {msg.encode('ascii', errors='replace').decode('ascii')}")

    update_step(1, "IN_PROGRESS", f"Connecting to `{target_ip}:{target_port}`...")
    log(f"🔌 Connecting to Receiver at `{target_ip}:{target_port}`...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)

    try:
        s.connect((target_ip, target_port))
    except Exception as e:
        update_step(1, "FAILED", f"Connection failed: {e}")
        return {"success": False, "error": f"Failed to connect to {target_ip}:{target_port} — {e}", "pipeline_state": pipeline_state}

    rng = np.random.default_rng()

    try:
        # 1. Generate Alice's random bits and bases
        alice_bits = rng.integers(0, 2, size=n_qubits).tolist()
        alice_bases = rng.integers(0, 2, size=n_qubits).tolist()

        sent_bits = list(alice_bits)
        sent_bases = list(alice_bases)

        if eve_active:
            log(f"🕵️ Eavesdropper (Eve) intercepting quantum channel at {eve_frac*100:.0f}% rate...")
            for i in range(n_qubits):
                if rng.random() < eve_frac:
                    eve_basis = int(rng.integers(0, 2))
                    if eve_basis == alice_bases[i]:
                        eve_result = alice_bits[i]
                    else:
                        eve_result = int(rng.integers(0, 2))
                    sent_bits[i] = eve_result
                    sent_bases[i] = eve_basis

        log(f"⚛️ Initiating QKD session `{session_id}` with {n_qubits} qubits...")

        init_payload = {
            "type": "QKD_INIT",
            "session_id": session_id,
            "n_qubits": n_qubits,
            "alice_bits": sent_bits,
            "alice_bases": sent_bases,
            "file_metadata": {
                "filename": file_name,
                "size": len(file_bytes),
                "mime_type": mime_type,
            },
        }

        # Send QKD_INIT payload
        _send_msg(s, json.dumps(init_payload).encode("utf-8"))
        update_step(1, "COMPLETED", f"Connected link for `{file_name}`")
        update_step(2, "IN_PROGRESS", f"Waiting for Bob to measure {n_qubits} qubits...")

        # 2. Wait for Bob's measurement response
        bob_resp_raw = _recv_msg(s)
        if not bob_resp_raw:
            update_step(2, "FAILED", "No measurement response from Bob")
            return {"success": False, "error": "No response received from Bob.", "pipeline_state": pipeline_state}
        bob_resp = json.loads(bob_resp_raw.decode("utf-8"))

        bob_bases = bob_resp["bob_bases"]

        # 3. Basis Sifting & Sample Selection
        matching_indices = [
            i for i in range(n_qubits) if alice_bases[i] == bob_bases[i]
        ]
        sifted_len = len(matching_indices)

        if sifted_len == 0:
            update_step(2, "FAILED", "Zero matching bases")
            return {"success": False, "error": "Zero matching bases found between Alice and Bob.", "pipeline_state": pipeline_state}

        # Select sample for public QBER check
        n_sample = max(1, int(sifted_len * sample_fraction))
        sample_positions = rng.choice(sifted_len, size=n_sample, replace=False).tolist()
        sample_indices = [matching_indices[pos] for pos in sample_positions]
        alice_sample_bits = [alice_bits[idx] for idx in sample_indices]

        update_step(2, "COMPLETED", f"Matching bases sifted: {sifted_len} bits")
        update_step(3, "IN_PROGRESS", f"Auditing {n_sample} public bit samples for QBER...")

        # Send sifting details to Bob
        log(f"🔍 Basis Sifting completed — Matching bases: {sifted_len} | Sacrificing {n_sample} bits for QBER check.")
        _send_msg(s, json.dumps({
            "type": "SIFT_BASES",
            "matching_indices": matching_indices,
            "sample_indices": sample_indices,
            "alice_sample_bits": alice_sample_bits,
        }).encode("utf-8"))

        # 4. Receive Security Decision from Bob
        decision_raw = _recv_msg(s)
        if not decision_raw:
            update_step(3, "FAILED", "Did not receive security decision")
            return {"success": False, "error": "Did not receive security decision from Bob.", "pipeline_state": pipeline_state}
        decision = json.loads(decision_raw.decode("utf-8"))

        qber = decision["qber"]
        qber_pct = decision["qber_pct"]
        is_secure = decision["is_secure"]

        if not is_secure:
            update_step(3, "ABORTED", f"🚨 Eavesdropper detected! QBER {qber_pct:.2f}% > 11%")
            log(f"🚨 QKD KEY REJECTED BY BOB! Measured QBER: {qber_pct:.2f}% > {QBER_THRESHOLD*100:.0f}% threshold. Eavesdropper detected!")
            return {
                "success": False,
                "session_id": session_id,
                "qber": qber,
                "qber_pct": qber_pct,
                "is_secure": False,
                "error": f"Transmission Aborted: Eavesdropper detected! QBER {qber_pct:.2f}% exceeds threshold.",
                "pipeline_state": pipeline_state,
            }

        update_step(3, "COMPLETED", f"✅ QBER {qber_pct:.2f}% safe (≤11%)")
        update_step(4, "IN_PROGRESS", "Deriving 256-bit AES key & encrypting file payload...")
        log(f"✅ QKD KEY SECURE! QBER {qber_pct:.2f}% is safe. Deriving AES-256 key...")

        # Extract Alice's secret key bits (excluding sample bits)
        sample_set = set(sample_indices)
        final_key_bits_alice = [
            alice_bits[idx] for idx in matching_indices if idx not in sample_set
        ]

        # Print first 10 bits of the final key for debugging key consistency across laptops
        key_preview_alice = "".join(str(b) for b in final_key_bits_alice[:10])
        log(f"🔑 [DEBUG] Alice's Final Key (first 10 bits): {key_preview_alice} (len: {len(final_key_bits_alice)})")

        # Derive AES Key
        aes_key = derive_aes_key(final_key_bits_alice)

        # 5. Encrypt File with AES Key
        log(f"🔒 Encrypting file `{file_name}` ({len(file_bytes)} bytes) using QKD-derived secret key...")
        encrypted_payload = encrypt_file_data(file_bytes, aes_key)

        update_step(4, "COMPLETED", f"File encrypted ({len(file_bytes)} bytes)")
        update_step(5, "IN_PROGRESS", "Streaming encrypted AES payload over socket...")

        # 6. Send Encrypted File Payload over network socket
        log("🚀 Transmitting AES-256 encrypted file payload over network channel...")
        _send_msg(s, json.dumps({
            "type": "ENCRYPTED_FILE_PAYLOAD",
            "encrypted_payload": encrypted_payload,
        }).encode("utf-8"))

        update_step(5, "COMPLETED", "Encrypted payload transmitted")
        update_step(6, "IN_PROGRESS", "Waiting for receiver HMAC & decryption ACK...")

        # Receive ACK from receiver
        ack_raw = _recv_msg(s)
        if ack_raw:
            ack = json.loads(ack_raw.decode("utf-8"))
            if ack.get("status") == "SUCCESS":
                update_step(6, "COMPLETED", f"🎉 Verified & delivered `{file_name}`!")
                log(f"🎉 TRANSMISSION COMPLETE & VERIFIED BY RECEIVER! File `{file_name}` delivered securely.")
                return {
                    "success": True,
                    "session_id": session_id,
                    "qber": qber,
                    "qber_pct": qber_pct,
                    "final_key_len": len(final_key_bits_alice),
                    "file_name": file_name,
                    "file_size": len(file_bytes),
                    "is_secure": True,
                    "pipeline_state": pipeline_state,
                }
            else:
                update_step(6, "FAILED", f"Receiver decryption failed: {ack.get('status')}")
                log(f"🚨 Receiver rejected file payload: {ack.get('status')}")
                return {
                    "success": False,
                    "session_id": session_id,
                    "qber": qber,
                    "qber_pct": qber_pct,
                    "is_secure": True,
                    "error": f"Receiver decryption failed ({ack.get('status')})",
                    "pipeline_state": pipeline_state,
                }

        update_step(6, "FAILED", "No confirmation ACK received")
        log("⚠️ File payload sent, but no confirmation ACK received from receiver.")
        return {
            "success": False,
            "session_id": session_id,
            "qber": qber,
            "qber_pct": qber_pct,
            "is_secure": True,
            "error": "File payload transmitted, but receiver failed to send delivery receipt ACK.",
            "pipeline_state": pipeline_state,
        }

    except Exception as e:
        update_step(6, "FAILED", f"Error: {e}")
        log(f"🚨 Transmission error: {e}")
        return {"success": False, "error": str(e), "pipeline_state": pipeline_state}
    finally:
        s.close()



def _send_msg(conn: socket.socket, data: bytes):
    length = len(data)
    conn.sendall(length.to_bytes(4, byteorder="big") + data)


def _recv_msg(conn: socket.socket) -> Optional[bytes]:
    try:
        header = b""
        while len(header) < 4:
            chunk = conn.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk
        length = int.from_bytes(header, byteorder="big")
        chunks = []
        bytes_recvd = 0
        while bytes_recvd < length:
            chunk = conn.recv(min(length - bytes_recvd, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_recvd += len(chunk)
        return b"".join(chunks)
    except Exception:
        return None


# =====================================================================
# LAPTOP 3: EVE MAN-IN-THE-MIDDLE (MITM) EAVESDROPPING PROXY NODE
# =====================================================================
class EveProxyListener:
    """
    Eve (Man-In-The-Middle Proxy) Listener node.
    Runs on Laptop 3 (or middleman machine).
    1. Listens for Alice's incoming QKD request on host:port (e.g. port 8503).
    2. Intercepts quantum bits (measures in random guessed bases, collapsing states).
    3. Forwards modified qubits to Bob's laptop (target_bob_ip:target_bob_port).
    4. Relays sifting & QBER response messages back to Alice.
    5. Displays live interception statistics.
    """
    def __init__(self, host: str = "0.0.0.0", port: int = 8503, target_bob_ip: str = "127.0.0.1", target_bob_port: int = 8502, eve_frac: float = 1.0):
        self.host = host
        self.port = port
        self.target_bob_ip = target_bob_ip
        self.target_bob_port = target_bob_port
        self.eve_frac = eve_frac
        self.server_socket: Optional[socket.socket] = None
        self.is_running = False
        self.logs: list = []
        self.interceptions_history: list = []
        self._thread: Optional[threading.Thread] = None

    def log(self, msg: str):
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {msg}"
        self.logs.append(formatted)
        try:
            print(formatted)
        except UnicodeEncodeError:
            print(formatted.encode('ascii', errors='replace').decode('ascii'))

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.logs.clear()
        self.interceptions_history.clear()
        self._thread = threading.Thread(target=self._run_proxy, daemon=True)
        self._thread.start()
        self.log(f"🕵️ Eve MITM Proxy Listener started on {self.host}:{self.port} -> Forwarding to Bob at {self.target_bob_ip}:{self.target_bob_port}")

    def stop(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.log("🛑 Eve MITM Proxy Listener stopped.")

    def _run_proxy(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
        except Exception as e:
            self.log(f"🚨 Proxy Socket bind failed: {e}")
            self.is_running = False
            return

        while self.is_running:
            try:
                alice_conn, alice_addr = self.server_socket.accept()
                alice_conn.settimeout(60.0)
                self.log(f"🕵️ Alice connected from {alice_addr[0]}:{alice_addr[1]} — Intercepting channel!")
                threading.Thread(target=self._handle_mitm, args=(alice_conn, alice_addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    self.log(f"Proxy accept error: {e}")
                break

    def _handle_mitm(self, alice_conn: socket.socket, alice_addr: Tuple[str, int]):
        rng = np.random.default_rng()
        bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_socket.settimeout(10.0)

        try:
            # Connect Eve to Bob's Laptop
            self.log(f"🔌 Connecting Eve Proxy to Bob at `{self.target_bob_ip}:{self.target_bob_port}`...")
            bob_socket.connect((self.target_bob_ip, self.target_bob_port))

            # 1. Receive Alice's QKD_INIT payload
            alice_init_raw = _recv_msg(alice_conn)
            if not alice_init_raw:
                return
            alice_init = json.loads(alice_init_raw.decode("utf-8"))

            session_id = alice_init["session_id"]
            n_qubits = alice_init["n_qubits"]
            alice_bits = alice_init["alice_bits"]
            alice_bases = alice_init["alice_bases"]
            file_meta = alice_init.get("file_metadata", {})

            self.log(f"⚡ Intercepted QKD init for session `{session_id}` ({n_qubits} qubits) for file `{file_meta.get('filename')}`")

            # 2. Eve active interception & state collapse
            intercepted_bits = list(alice_bits)
            intercepted_bases = list(alice_bases)
            eve_hits = 0
            eve_errors_introduced = 0

            for i in range(n_qubits):
                if rng.random() < self.eve_frac:
                    eve_hits += 1
                    eve_basis = int(rng.integers(0, 2))
                    if eve_basis == alice_bases[i]:
                        eve_result = alice_bits[i]
                    else:
                        eve_result = int(rng.integers(0, 2))
                        if eve_result != alice_bits[i]:
                            eve_errors_introduced += 1
                    
                    intercepted_bits[i] = eve_result
                    intercepted_bases[i] = eve_basis

            self.log(f"🕵️ Intercepted {eve_hits}/{n_qubits} qubits! Collapsed quantum state, introducing disturbance...")

            # Forward modified payload to Bob
            forward_payload = {
                "type": "QKD_INIT",
                "session_id": session_id,
                "n_qubits": n_qubits,
                "alice_bits": intercepted_bits,
                "alice_bases": intercepted_bases,
                "file_metadata": file_meta,
            }
            _send_msg(bob_socket, json.dumps(forward_payload).encode("utf-8"))

            # 3. Relay Bob's response back to Alice
            bob_resp_raw = _recv_msg(bob_socket)
            if bob_resp_raw:
                _send_msg(alice_conn, bob_resp_raw)

            # 4. Relay Alice's sifting payload to Bob
            alice_sift_raw = _recv_msg(alice_conn)
            if alice_sift_raw:
                _send_msg(bob_socket, alice_sift_raw)

            # 5. Relay Bob's security decision back to Alice
            bob_decision_raw = _recv_msg(bob_socket)
            if bob_decision_raw:
                decision = json.loads(bob_decision_raw.decode("utf-8"))
                qber_pct = decision.get("qber_pct", 0.0)
                is_sec = decision.get("is_secure", False)
                
                self.log(f"📊 Interception Result — Measured QBER on Bob: {qber_pct:.2f}% | Key Accepted: {is_sec}")
                if not is_sec:
                    self.log(f"🚨 Eavesdropping Detected! Bob & Alice automatically discarded key & aborted file transmission!")
                
                self.interceptions_history.append({
                    "session_id": session_id,
                    "n_qubits": n_qubits,
                    "eve_hits": eve_hits,
                    "qber_pct": qber_pct,
                    "blocked": not is_sec,
                    "filename": file_meta.get("filename"),
                    "timestamp": time.time(),
                })

                _send_msg(alice_conn, bob_decision_raw)

                if is_sec:
                    # Relay encrypted file payload from Alice to Bob
                    encrypted_file_raw = _recv_msg(alice_conn)
                    if encrypted_file_raw:
                        _send_msg(bob_socket, encrypted_file_raw)
                        # Relay ACK from Bob back to Alice
                        ack_raw = _recv_msg(bob_socket)
                        if ack_raw:
                            _send_msg(alice_conn, ack_raw)

        except Exception as e:
            self.log(f"🚨 Error in MITM proxy: {e}")
        finally:
            alice_conn.close()
            bob_socket.close()

