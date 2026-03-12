" backend/detection/layer1_filter.py"
# """
# Layer 1 Filter — Cloud Sentinel
# ================================
# Fast gate: checks TTL and packet size.
# If within safe thresholds → PASS (no Layer 2 needed).
# If outside → forward to Layer 2 for deep scan.
#
# Designed to run in < 1ms.
# """
#
# # ── Thresholds (tune these to your environment) ───────────────────────────────
#
# TTL_MIN          = 30      # anything below this is suspicious (spoofed/dying packet)
# TTL_MAX          = 128     # normal OS defaults: 64 (Linux), 128 (Windows), 255 (Cisco)
# PACKET_SIZE_MIN  = 20      # bytes — minimum valid IP packet
# PACKET_SIZE_MAX  = 65535   # bytes — theoretical IP max; flag anything above ~9000 for Ethernet
# DURATION_MAX_MS  = 3000    # ms — Lambda functions > 3s are suspicious
# DURATION_MIN_MS  = 0       # ms
#
#
# class Layer1Filter:
#     """
#     Stateless first-pass filter.
#     Returns a decision dict in microseconds.
#     """
#
#     def __init__(
#         self,
#         ttl_min: int = TTL_MIN,
#         ttl_max: int = TTL_MAX,
#         size_min: int = PACKET_SIZE_MIN,
#         size_max: int = PACKET_SIZE_MAX,
#         duration_max_ms: float = DURATION_MAX_MS,
#     ):
#         self.ttl_min        = ttl_min
#         self.ttl_max        = ttl_max
#         self.size_min       = size_min
#         self.size_max       = size_max
#         self.duration_max   = duration_max_ms
#
#     def check(self, packet: dict) -> dict:
#         """
#         Run Layer 1 checks.
#
#         Args:
#             packet: dict with keys:
#                 - ttl            (int)   IP Time-To-Live
#                 - packet_size    (int)   bytes
#                 - duration       (float) ms
#
#         Returns:
#             {
#                 "pass":    bool,   # True = safe, skip Layer 2
#                 "reason":  str,    # why it was flagged or passed
#                 "checks":  dict    # individual check results
#             }
#         """
#         ttl          = packet.get("ttl", 64)
#         packet_size  = packet.get("packet_size", 512)
#         duration     = packet.get("duration", 0)
#
#         checks = {
#             "ttl_ok":      self.ttl_min <= ttl <= self.ttl_max,
#             "size_ok":     self.size_min <= packet_size <= self.size_max,
#             "duration_ok": duration <= self.duration_max,
#         }
#
#         passed = all(checks.values())
#
#         if passed:
#             reason = "All Layer 1 checks passed — packet within safe thresholds"
#         else:
#             failed = [k for k, v in checks.items() if not v]
#             reason = f"Layer 1 flagged: {', '.join(failed)}"
#
#         return {
#             "pass":   passed,
#             "reason": reason,
#             "checks": checks,
#             "values": {
#                 "ttl":         ttl,
#                 "packet_size": packet_size,
#                 "duration_ms": duration,
#             }
#         }