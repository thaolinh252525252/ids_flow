import { useEffect, useMemo, useState } from "react";
import { getAttacks, getConfig, getFlows, getStats, setConfig } from "../api";
import {
  Box,
  Button,
  Card,
  CardContent,
  Divider,
  FormControlLabel,
  Grid,
  Switch,
  TextField,
  Typography,
  Chip,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tooltip,
  TableContainer,
} from "@mui/material";
import StatCards from "../components/StatCards";

import {
  AlertsPerMinute,
  StageSeverityBreakdown,
  SuspiciousDistribution,
  TopFamiliesChart,
  TopSuspiciousTable,
} from "../components/Charts";

function safeNum(x, d = null) {
  const n = Number(x);
  return Number.isFinite(n) ? n : d;
}

function fmtTs(ts) {
  const n = safeNum(ts, 0);
  if (!n) return "—";
  return new Date(n * 1000).toLocaleString();
}

function protoName(p) {
  const n = safeNum(p, null);
  if (n === 6) return "TCP";
  if (n === 17) return "UDP";
  if (n === 1) return "ICMP";
  return n == null ? "—" : String(n);
}

function fmtAddr(ip, port) {
  if (!ip) return "—";
  if (port == null) return String(ip);
  return `${ip}:${port}`;
}

function verdictColor(v) {
  if (v === "attack") return "error";
  if (v === "suspicious") return "warning";
  if (v === "benign") return "success";
  return "default";
}
// function safeNum(x, d = null) {
//   const n = Number(x);
//   return Number.isFinite(n) ? n : d;
// }
// function fmtTs(ts) {
//   const n = safeNum(ts, 0);
//   if (!n) return "N/A";
//   return new Date(n * 1000).toLocaleString();
// }
function pillColor(verdict) {
  if (verdict === "attack") return "error";
  if (verdict === "suspicious") return "warning";
  if (verdict === "benign") return "success";
  return "default";
}

function FlowsTable({
  rows,
  height = 780,
  search,
  onSearch,
  paused,
  onPaused,
  limit,
  onLimit,
}) {
  return (
    <Card sx={{ height }}>
      <CardContent
        sx={{ height: "100%", display: "flex", flexDirection: "column" }}
      >
        <Stack
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          sx={{ mb: 1 }}
        >
          <Typography variant="h6" sx={{ fontWeight: 900 }}>
            All flows (realtime)
          </Typography>
          <Stack direction="row" spacing={1} alignItems="center">
            <TextField
              size="small"
              placeholder="search: verdict / stage / family"
              value={search}
              onChange={(e) => onSearch(e.target.value)}
              sx={{ width: 260 }}
            />
            <TextField
              size="small"
              label="limit"
              type="number"
              inputProps={{ min: 50, max: 5000, step: 50 }}
              value={limit}
              onChange={(e) => onLimit(Number(e.target.value || 1000))}
              sx={{ width: 110 }}
            />
            <FormControlLabel
              control={
                <Switch
                  checked={paused}
                  onChange={(e) => onPaused(e.target.checked)}
                />
              }
              label="Pause"
            />
          </Stack>
        </Stack>

        <Divider sx={{ mb: 1.5 }} />

        <TableContainer sx={{ maxHeight: "100%" }}>
          <Table stickyHeader size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 900, whiteSpace: "nowrap" }}>
                  Time
                </TableCell>
                <TableCell sx={{ fontWeight: 900 }}>Proto</TableCell>
                <TableCell sx={{ fontWeight: 900 }}>Source</TableCell>
                <TableCell sx={{ fontWeight: 900 }}>Destination</TableCell>
                <TableCell sx={{ fontWeight: 900 }} align="right">
                  Pkts
                </TableCell>
                <TableCell sx={{ fontWeight: 900 }} align="right">
                  Bytes
                </TableCell>
                <TableCell sx={{ fontWeight: 900 }} align="right">
                  Dur(ms)
                </TableCell>
                <TableCell sx={{ fontWeight: 900 }}>Verdict</TableCell>
                <TableCell sx={{ fontWeight: 900 }}>Stage</TableCell>
                <TableCell sx={{ fontWeight: 900 }} align="right">
                  p_attack
                </TableCell>
                <TableCell sx={{ fontWeight: 900 }}>Rule</TableCell>
                <TableCell sx={{ fontWeight: 900 }}>Family</TableCell>
              </TableRow>
            </TableHead>

            <TableBody>
              {rows.map((r, idx) => {
                const m = r?.meta || {};
                const v = String(r?.verdict ?? "unknown");
                const stage = String(r?.stage ?? "—");
                const p = safeNum(r?.p_attack, null);

                const src = fmtAddr(m.src_ip, m.src_port);
                const dst = fmtAddr(m.dst_ip, m.dst_port);

                const pkts = safeNum(m.pkts, null);
                const bytes = safeNum(m.bytes, null);
                const dur = safeNum(m.dur_ms, null);

                const fam = r?.family ?? "—";
                const famConf = safeNum(r?.family_conf, null);

                // rule name (tuỳ backend bạn attach)
                const ruleName =
                  r?.rule_name ??
                  r?.rule?.name ??
                  (typeof r?.rule_info === "string"
                    ? r.rule_info
                    : r?.rule_info?.name);

                return (
                  <TableRow key={idx} hover>
                    <TableCell sx={{ whiteSpace: "nowrap" }}>
                      {fmtTs(r?.ts)}
                    </TableCell>
                    <TableCell>{protoName(m.proto)}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>
                      {src}
                    </TableCell>
                    <TableCell sx={{ fontFamily: "monospace" }}>
                      {dst}
                    </TableCell>

                    <TableCell align="right">
                      {pkts == null ? "—" : pkts.toFixed(0)}
                    </TableCell>
                    <TableCell align="right">
                      {bytes == null ? "—" : bytes.toFixed(0)}
                    </TableCell>
                    <TableCell align="right">
                      {dur == null ? "—" : dur.toFixed(0)}
                    </TableCell>

                    <TableCell>
                      <Chip
                        size="small"
                        label={v}
                        color={verdictColor(v)}
                        variant="outlined"
                      />
                    </TableCell>

                    <TableCell>{stage}</TableCell>
                    <TableCell align="right">
                      {p == null ? "—" : p.toFixed(6)}
                    </TableCell>

                    <TableCell>
                      {ruleName ? (
                        <Tooltip
                          title={
                            r?.rule_info
                              ? typeof r.rule_info === "string"
                                ? r.rule_info
                                : JSON.stringify(r.rule_info, null, 2)
                              : ruleName
                          }
                        >
                          <Chip
                            size="small"
                            variant="outlined"
                            label={ruleName}
                          />
                        </Tooltip>
                      ) : (
                        "—"
                      )}
                    </TableCell>

                    <TableCell>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <span>{fam}</span>
                        {famConf != null && (
                          <Chip
                            size="small"
                            variant="outlined"
                            label={(famConf * 100).toFixed(1) + "%"}
                          />
                        )}
                      </Stack>
                    </TableCell>
                  </TableRow>
                );
              })}

              {rows.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={12}
                    sx={{ py: 4, textAlign: "center", color: "text.secondary" }}
                  >
                    No flows yet. Start collector + generate traffic.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>

        <Typography variant="caption" sx={{ mt: 1, color: "text.secondary" }}>
          Showing newest first. Backend keeps up to max_flows (deque maxlen), UI
          only fetches “limit” rows.
        </Typography>
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [cfg, setCfg] = useState(null);
  const [attacks, setAttacks] = useState([]);
  const [flows, setFlows] = useState([]);

  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState("");
  const [flowLimit, setFlowLimit] = useState(1000);

  async function refresh() {
    const [s, c, a, f] = await Promise.all([
      getStats(),
      getConfig(),
      getAttacks(5000),
      getFlows(flowLimit),
    ]);
    setStats(s);
    setCfg(c);
    setAttacks(Array.isArray(a) ? a : []);
    setFlows(Array.isArray(f) ? f : []);
  }

  useEffect(() => {
    refresh();
    const t = setInterval(() => {
      if (!paused) refresh();
    }, 1200);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paused, flowLimit]);

  const filteredFlows = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return flows;
    return flows.filter((r) => {
      const s =
        `${r?.verdict ?? ""} ${r?.stage ?? ""} ${r?.family ?? ""}`.toLowerCase();
      return s.includes(q);
    });
  }, [flows, search]);

  if (!stats || !cfg) return <Typography>Loading...</Typography>;

  const counts = stats.counts || {};
  const last = stats.last_ts
    ? new Date(stats.last_ts * 1000).toLocaleString()
    : "N/A";

  return (
    <Box sx={{ pb: 3 }}>
      <StatCards counts={counts} queueLen={stats.queue_len} last={last} />

      {/* MAIN LAYOUT: left table, right charts */}
      <Grid container spacing={2} sx={{ mt: 0.5 }} alignItems="stretch">
        {/* LEFT: FLOWS TABLE */}
        <Grid item xs={12} lg={5}>
          <FlowsTable
            rows={filteredFlows}
            height={780}
            search={search}
            onSearch={setSearch}
            paused={paused}
            onPaused={setPaused}
            limit={flowLimit}
            onLimit={setFlowLimit}
          />
        </Grid>

        {/* RIGHT: CHARTS */}
        <Grid item xs={12} lg={7}>
          <Grid container spacing={2} alignItems="stretch">
            <Grid item xs={12} md={6}>
              <Card sx={{ height: 380 }}>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
                    Alerts per minute
                  </Typography>
                  <Box sx={{ height: 300 }}>
                    <AlertsPerMinute rows={attacks} height={300} />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ height: 380 }}>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
                    Stage × severity
                  </Typography>
                  <Box sx={{ height: 300 }}>
                    <StageSeverityBreakdown rows={attacks} height={300} />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ height: 380 }}>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
                    Suspicious distribution
                  </Typography>
                  <Box sx={{ height: 300 }}>
                    <SuspiciousDistribution rows={attacks} height={300} />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ height: 380 }}>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
                    Top families
                  </Typography>
                  <Box sx={{ height: 300 }}>
                    <TopFamiliesChart rows={attacks} k={8} height={300} />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Top suspicious table */}
            <Grid item xs={12}>
              <TopSuspiciousTable rows={attacks} limit={15} />
            </Grid>

            {/* Runtime config */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 800 }}>
                    Runtime Config
                  </Typography>
                  <Divider sx={{ my: 1.5 }} />
                  <Grid container spacing={2} alignItems="center">
                    <Grid item>
                      <TextField
                        size="small"
                        label="tau_low"
                        type="number"
                        inputProps={{ step: 0.01 }}
                        value={cfg.tau_low}
                        onChange={(e) =>
                          setCfg({ ...cfg, tau_low: Number(e.target.value) })
                        }
                      />
                    </Grid>
                    <Grid item>
                      <TextField
                        size="small"
                        label="tau_high"
                        type="number"
                        inputProps={{ step: 0.01 }}
                        value={cfg.tau_high}
                        onChange={(e) =>
                          setCfg({ ...cfg, tau_high: Number(e.target.value) })
                        }
                      />
                    </Grid>
                    <Grid item>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={!!cfg.enable_rules}
                            onChange={(e) =>
                              setCfg({ ...cfg, enable_rules: e.target.checked })
                            }
                          />
                        }
                        label="enable_rules"
                      />
                    </Grid>
                    <Grid item>
                      <Button
                        variant="contained"
                        onClick={async () => setCfg(await setConfig(cfg))}
                      >
                        Save
                      </Button>
                    </Grid>
                    <Grid item>
                      <Button variant="outlined" onClick={refresh}>
                        Refresh
                      </Button>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Box>
  );
}
