import {
  Box,
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Chip,
  Stack,
} from "@mui/material";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
  Legend,
} from "recharts";

function safeNum(x, d = null) {
  const n = Number(x);
  return Number.isFinite(n) ? n : d;
}

function fmtTs(ts) {
  const n = safeNum(ts, 0);
  if (!n) return "N/A";
  return new Date(n * 1000).toLocaleString();
}

function fmtP(x, k = 4) {
  const n = safeNum(x, null);
  if (n == null) return "—";
  return n.toFixed(k);
}

/** --------- DATA HELPERS --------- **/

export function bucketPerMinute(rows) {
  const m = new Map();
  for (const r of rows || []) {
    const ts = safeNum(r?.ts, null);
    if (!ts || ts <= 0) continue;
    const minute = Math.floor(ts / 60) * 60;

    const cur = m.get(minute) || {
      t: minute,
      time: "",
      attack: 0,
      suspicious: 0,
      rule: 0,
    };
    if (r?.verdict === "attack") cur.attack += 1;
    if (r?.verdict === "suspicious") cur.suspicious += 1;
    if (r?.stage === "rule") cur.rule += 1;

    m.set(minute, cur);
  }
  return [...m.values()]
    .sort((a, b) => a.t - b.t)
    .map((x) => ({ ...x, time: new Date(x.t * 1000).toLocaleTimeString() }));
}

export function topFamilies(rows, k = 8) {
  const m = new Map();
  for (const r of rows || []) {
    const fam = r?.family;
    if (!fam) continue;
    m.set(fam, (m.get(fam) || 0) + 1);
  }
  return [...m.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, k)
    .map(([name, count]) => ({ name, count }));
}

export function stageSeverity(rows) {
  // severity: rule_info?.severity, nếu không có thì "none"
  const stages = ["rule", "binary", "family"];
  const sevKeys = ["high", "medium", "none"];
  const init = {};
  for (const st of stages)
    init[st] = { stage: st, high: 0, medium: 0, none: 0 };

  for (const r of rows || []) {
    const st = r?.stage || "binary";
    if (!init[st]) init[st] = { stage: st, high: 0, medium: 0, none: 0 };

    const sev = (r?.rule_info?.severity || "none").toLowerCase();
    const key = sevKeys.includes(sev) ? sev : "none";
    init[st][key] += 1;
  }
  return Object.values(init);
}

export function suspiciousBins(rows, tauLow = 0.2, tauHigh = 0.95) {
  const bins = [
    { name: `${tauLow.toFixed(2)}–0.40`, a: tauLow, b: 0.4, count: 0 },
    { name: `0.40–0.60`, a: 0.4, b: 0.6, count: 0 },
    { name: `0.60–0.80`, a: 0.6, b: 0.8, count: 0 },
    { name: `0.80–${tauHigh.toFixed(2)}`, a: 0.8, b: tauHigh, count: 0 },
  ];

  for (const r of rows || []) {
    if (r?.verdict !== "suspicious") continue;
    const p = safeNum(r?.p_attack, null);
    if (p == null) continue;
    for (const bin of bins) {
      if (p >= bin.a && p < bin.b) {
        bin.count += 1;
        break;
      }
    }
  }
  return bins.map(({ name, count }) => ({ name, count }));
}

export function topSuspicious(rows, limit = 12) {
  return (rows || [])
    .filter((r) => r?.verdict === "suspicious")
    .map((r) => ({ ...r, p_attack: safeNum(r?.p_attack, null) }))
    .filter((r) => r.p_attack != null)
    .sort((a, b) => (b.p_attack ?? 0) - (a.p_attack ?? 0))
    .slice(0, limit);
}

/** --------- CHART COMPONENTS (NAMED EXPORTS) --------- **/

export function AlertsPerMinute({ rows, height = 240 }) {
  const data = bucketPerMinute(rows);
  return (
    <Box sx={{ width: "100%", minHeight: height, height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
          <XAxis dataKey="time" tick={{ fontSize: 12 }} />
          <YAxis />
          <Tooltip />
          <Line type="monotone" dataKey="attack" dot={false} strokeWidth={2} />
          <Line
            type="monotone"
            dataKey="suspicious"
            dot={false}
            strokeWidth={2}
          />
          <Line type="monotone" dataKey="rule" dot={false} strokeWidth={2} />
        </LineChart>
      </ResponsiveContainer>
    </Box>
  );
}

export function StageSeverityBreakdown({ rows, height = 240 }) {
  const data = stageSeverity(rows);
  return (
    <Box sx={{ width: "100%", minHeight: height, height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
          <XAxis dataKey="stage" tick={{ fontSize: 12 }} />
          <YAxis />
          <Tooltip />
          <Legend />
          <Bar dataKey="high" name="high" stackId="a" fill="#ff5c5c" />
          <Bar dataKey="medium" name="medium" stackId="a" fill="#f6c343" />
          <Bar dataKey="none" name="none" stackId="a" fill="#7a8aa6" />
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}

export function SuspiciousDistribution({
  rows,
  tauLow = 0.2,
  tauHigh = 0.95,
  height = 240,
}) {
  const data = suspiciousBins(rows, tauLow, tauHigh);
  return (
    <Box sx={{ width: "100%", minHeight: height, height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
          <XAxis dataKey="name" tick={{ fontSize: 12 }} />
          <YAxis />
          <Tooltip />
          <Bar dataKey="count" />
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}

import { LabelList } from "recharts"; // nếu chưa có

export function TopFamiliesChart({ rows, k = 8, height = 240 }) {
  const data = topFamilies(rows, k);

  return (
    <Box sx={{ width: "100%", height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          // làm plot "đầy" hơn
          margin={{ top: 18, right: 8, bottom: 30, left: 0 }}
          barCategoryGap="8%" // giảm khoảng trống giữa các category
          barGap={2}
        >
          <CartesianGrid strokeDasharray="3 3" opacity={0.15} />

          <XAxis
            dataKey="name"
            interval={0}
            tick={{ fontSize: 12 }}
            tickMargin={6}
            angle={-30}
            textAnchor="end"
            height={30} // giảm đáy (vì đã xoay)
          />

          <YAxis width={34} tick={{ fontSize: 11 }} allowDecimals={false} />
          <Tooltip />

          <Bar dataKey="count" barSize={44}>
            {/* hiện count gọn trên đầu cột */}
            <LabelList
              dataKey="count"
              position="top"
              offset={6}
              style={{ fontSize: 12 }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Box>
  );
}

export function TopSuspiciousTable({ rows, limit = 12 }) {
  const data = topSuspicious(rows, limit);
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
          Top suspicious
        </Typography>

        <Stack direction="row" spacing={1} sx={{ mb: 1, flexWrap: "wrap" }}>
          <Chip size="small" label={`rows: ${data.length}`} />
          <Chip size="small" label={`sorted by p_attack`} />
        </Stack>

        <Box sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>p_attack</TableCell>
                <TableCell>Stage</TableCell>
                <TableCell>Rule</TableCell>
                <TableCell>Sev</TableCell>
                <TableCell>GT</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.map((r, idx) => (
                <TableRow key={`${r.ts || 0}-${idx}`}>
                  <TableCell>{fmtTs(r.ts)}</TableCell>
                  <TableCell>{fmtP(r.p_attack, 4)}</TableCell>
                  <TableCell>{r.stage || "—"}</TableCell>
                  <TableCell>{r?.rule_info?.rule || "—"}</TableCell>
                  <TableCell>{r?.rule_info?.severity || "—"}</TableCell>
                  <TableCell>{r.gt_attack || "—"}</TableCell>
                </TableRow>
              ))}
              {data.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} sx={{ opacity: 0.7 }}>
                    No suspicious rows (try lowering tau_high or replay more
                    data).
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </Box>
      </CardContent>
    </Card>
  );
}
