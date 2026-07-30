import threading
import socket
import json
import time
import numpy as np
from qkd_network import QKDNetworkListener, transmit_file_over_qkd

# Start listener on port 8900
listener = QKDNetworkListener(host="127.0.0.1", port=8900)
listener.start()

time.sleep(1)

# Alice transmits file
file_data = b"Hello, this is some PDF file data!" * 100
res = transmit_file_over_qkd(
    target_ip="127.0.0.1",
    target_port=8900,
    file_name="test.pdf",
    file_bytes=file_data,
    mime_type="application/pdf",
    n_qubits=400,
    sample_fraction=0.5
)

print("Alice Result:", res)
if listener.last_received_file:
    print("Bob Decryption Status:", listener.last_received_file["status_msg"])
else:
    print("Bob did not receive file.")

listener.stop()
