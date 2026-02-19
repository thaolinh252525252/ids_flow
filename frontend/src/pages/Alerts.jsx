import { useEffect, useMemo, useState } from "react";
import { getAttacks } from "../api";
import { Box, Card, CardContent, Chip, Stack, Typography } from "@mui/material";
import AlertsTable from "../components/AlertsTable";
import AlertDetailDialog from "../components/AlertDetailDialog";

function normalizeAttack(r) {
  if (!r || typeof r !== "object") return {};

  return {
    ts: r.ts ?? null,
    verdict: r.verdict ?? "unknown",
    stage: r.stage ?? "binary",
    p_attack: r.p_attack ?? null,
    family: r.family ?? null,
    family_conf: r.family_conf ?? null,
    gt_attack: r.gt_attack ?? null,
    gt_label: r.gt_label ?? null,
    rule_info: r.rule_info ?? null,
  };
}

export default function Alerts() {
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);

  async function refresh() {
    const data = await getAttacks(800);
    // data MUST be array of objects
    const arr = Array.isArray(data) ? data : [];
    const norm = arr.map(normalizeAttack);
    setRows(norm);

    console.log("raw[0]:", arr[0]);
    console.log("norm[0]:", norm[0]);
    console.log("raw keys:", arr[0] && Object.keys(arr[0]));
    console.log("norm keys:", norm[0] && Object.keys(norm[0]));

    // debug 1 sample (xem nó có ts/p_attack/family ko)
    if (arr.length > 0) {
      // eslint-disable-next-line no-console
      console.log("[attacks sample]", arr[0]);
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 1500);
    return () => clearInterval(t);
  }, []);

  const summary = useMemo(() => {
    let attack = 0,
      suspicious = 0,
      rule = 0;
    for (const r of rows) {
      if (r?.verdict === "attack") attack++;
      if (r?.verdict === "suspicious") suspicious++;
      if (r?.stage === "rule") rule++;
    }
    return { attack, suspicious, rule, total: rows.length };
  }, [rows]);

  return (
    <Box>
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="h6" sx={{ fontWeight: 800 }}>
            Live Alerts
          </Typography>
          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap" }}>
            <Chip label={`total: ${summary.total}`} />
            <Chip color="error" label={`attack: ${summary.attack}`} />
            <Chip color="warning" label={`suspicious: ${summary.suspicious}`} />
            <Chip color="primary" label={`rule: ${summary.rule}`} />
          </Stack>
          <Typography variant="caption" sx={{ opacity: 0.7 }}>
            Click 1 row để xem chi tiết (bao gồm family/gt_attack khi replay).
          </Typography>
        </CardContent>
      </Card>

      <AlertsTable rows={rows} onSelect={setSelected} />
      <AlertDetailDialog item={selected} onClose={() => setSelected(null)} />
    </Box>
  );
}
