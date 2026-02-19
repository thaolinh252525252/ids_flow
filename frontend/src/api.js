import axios from "axios";

export async function getStats() {
  const r = await axios.get("/api/stats");
  return r.data;
}
export async function getAttacks(limit = 300) {
  const r = await axios.get(`/api/attacks?limit=${limit}`);
  return r.data;
}
export async function getConfig() {
  const r = await axios.get("/api/config");
  return r.data;
}
export async function setConfig(cfg) {
  const r = await axios.post("/api/config", cfg);
  return r.data;
}
