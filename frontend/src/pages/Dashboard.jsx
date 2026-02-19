import { useEffect, useState } from "react";
import { getAttacks, getConfig, getStats, setConfig } from "../api";
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
} from "@mui/material";
import StatCards from "../components/StatCards";

import {
  AlertsPerMinute,
  StageSeverityBreakdown,
  SuspiciousDistribution,
  TopFamiliesChart,
  TopSuspiciousTable,
} from "../components/Charts";

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [cfg, setCfg] = useState(null);
  const [attacks, setAttacks] = useState([]);

  async function refresh() {
    const [s, c, a] = await Promise.all([
      getStats(),
      getConfig(),
      getAttacks(5000),
    ]);
    setStats(s);
    setCfg(c);
    setAttacks(Array.isArray(a) ? a : []);
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 1500);
    return () => clearInterval(t);
  }, []);

  if (!stats || !cfg) return <Typography>Loading...</Typography>;

  const counts = stats.counts || {};
  const last = stats.last_ts
    ? new Date(stats.last_ts * 1000).toLocaleString()
    : "N/A";

  return (
    <Box sx={{ pb: 3 }}>
      <StatCards counts={counts} queueLen={stats.queue_len} last={last} />

      {/* ROW 1: 4 charts */}
      <Grid container spacing={2} sx={{ mt: 0.5 }} alignItems="stretch">
        <Grid item xs={12} sm={6} lg={3}>
          <Card sx={{ height: 340 }}>
            <CardContent>
              <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
                Alerts per minute
              </Typography>
              {/* Chart container phải có height cố định */}
              <Box sx={{ height: 260 }}>
                <AlertsPerMinute rows={attacks} height={260} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} lg={3}>
          <Card sx={{ height: 340 }}>
            <CardContent>
              <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
                Stage × severity
              </Typography>
              <Box sx={{ height: 260 }}>
                <StageSeverityBreakdown rows={attacks} height={260} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} lg={3}>
          <Card sx={{ height: 340 }}>
            <CardContent>
              <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
                Suspicious distribution
              </Typography>
              <Box sx={{ height: 260 }}>
                <SuspiciousDistribution rows={attacks} height={260} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} lg={3}>
          <Card sx={{ height: 340 }}>
            <CardContent>
              <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
                Top families
              </Typography>
              <Box sx={{ height: 260 }}>
                <TopFamiliesChart rows={attacks} k={8} height={260} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* ROW 2: Top suspicious full width */}
      <Grid container spacing={2} sx={{ mt: 0.5 }}>
        <Grid item xs={12}>
          <TopSuspiciousTable rows={attacks} limit={15} />
        </Grid>
      </Grid>

      {/* Runtime Config giữ như bạn đang có */}
      <Card sx={{ mt: 2 }}>
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
    </Box>
  );
}
