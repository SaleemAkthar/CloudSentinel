export function fmtTime(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function fmtScore(n) {
  if (typeof n !== "number") return "—";
  return n.toFixed(2);
}
