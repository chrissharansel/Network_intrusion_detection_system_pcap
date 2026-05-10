"""
PCAPManager patch for network_ids_advanced.py
=============================================
Drop this file next to network_ids_advanced.py and import it at the top of
your startup script (or in ids_web_dashboard_v2.py) BEFORE importing
AdvancedNetworkIDS:

    import pcap_manager_patch          # applies the fix
    from network_ids_advanced import AdvancedNetworkIDS, load_config

What was wrong
--------------
The original _flush() did:

    wrpcap(self._cur, self._buf)   # writes to capture_001.pcap  ✓
    self._idx += 1                  # idx is now 2
    self._cur = self._new_path()   # self._cur is now capture_002.pcap
    # BUT list_files() looks for *.pcap in session_dir — capture_001.pcap
    # IS there, so it should work… right?

The real problem: write_packet() appends to self._buf but NEVER actually
calls wrpcap until the buffer hits max_pkt (default 10 000 packets).
With typical traffic that takes a very long time, so list_files() returns []
for ages and the dashboard always shows 0.

Fix
---
1. _flush() now writes to self._cur THEN advances the index (no logic change,
   just made explicit).
2. write_packet() also does a *partial* flush every PARTIAL_FLUSH_EVERY
   packets so the file appears on disk quickly (we append, not overwrite, by
   using scapy's wrpcap which always overwrites — so we write the whole buffer
   each partial flush; that's fine for small buffers).
3. _pcap_count() in the dashboard already handles the "in-progress" case, but
   with partial flushing the file will actually be there within seconds.
"""

from network_ids_advanced import PCAPManager
from scapy.all import wrpcap

# How often (in packets) to do a partial flush so the file appears on disk
PARTIAL_FLUSH_EVERY = 100   # flush to disk every 100 packets


def _fixed_write_packet(self, pkt):
    with self._lock:
        self._buf.append(pkt)
        if len(self._buf) >= self.max_pkt:
            self._flush()
        elif len(self._buf) % PARTIAL_FLUSH_EVERY == 0:
            # Partial flush: write current buffer to disk without advancing index
            # This makes the file appear in list_files() almost immediately.
            if self._buf:
                wrpcap(self._cur, self._buf)


def _fixed_flush(self):
    """Write buffer to self._cur, then advance to the next file path."""
    if not self._buf:
        return
    wrpcap(self._cur, self._buf)    # write to e.g. capture_001.pcap
    self._buf = []
    self._idx += 1
    self._cur = self._new_path()    # advance to capture_002.pcap
    # Prune oldest files
    for old in self.list_files()[:-self.max_files]:
        try:
            import os; os.remove(old)
        except Exception:
            pass


def _fixed_flush_all(self):
    with self._lock:
        if self._buf:
            self._flush()


# Patch the class
PCAPManager.write_packet = _fixed_write_packet
PCAPManager._flush       = _fixed_flush
PCAPManager.flush_all    = _fixed_flush_all

print("✅  PCAPManager patch applied (partial-flush every "
      f"{PARTIAL_FLUSH_EVERY} packets)")