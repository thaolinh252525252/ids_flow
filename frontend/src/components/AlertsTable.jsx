import { DataGrid } from "@mui/x-data-grid";
import { Box, Chip } from "@mui/material";

function fmtTs(ts) {
  if (ts == null) return "N/A";
  const n = Number(ts);
  if (!Number.isFinite(n) || n <= 0) return "N/A";
  return new Date(n * 1000).toLocaleString();
}
function fmtNum(x, k = 4) {
  if (x == null) return "—";
  const n = Number(x);
  if (!Number.isFinite(n)) return "—";
  return n.toFixed(k);
}

export default function AlertsTable({ rows, onSelect }) {
  const safeRows = Array.isArray(rows) ? rows : [];

  const columns = [
    {
      field: "ts",
      headerName: "Time",
      flex: 1.25,
      sortable: false,
      renderCell: (p) => fmtTs(p?.row?.ts),
    },
    {
      field: "verdict",
      headerName: "Verdict",
      flex: 0.8,
      renderCell: (p) => {
        const v = p?.row?.verdict;
        if (v === "attack")
          return <Chip color="error" label="attack" size="small" />;
        if (v === "suspicious")
          return <Chip color="warning" label="suspicious" size="small" />;
        return <Chip label={v || "unknown"} size="small" />;
      },
    },
    { field: "stage", headerName: "Stage", flex: 0.7 },
    {
      field: "p_attack",
      headerName: "p_attack",
      flex: 0.8,
      sortable: false,
      renderCell: (p) => fmtNum(p?.row?.p_attack, 4),
    },
    {
      field: "rule",
      headerName: "Rule",
      flex: 1.0,
      sortable: false,
      valueGetter: (p) => p?.row?.rule_info?.rule ?? null,
      renderCell: (p) => p?.row?.rule_info?.rule ?? "—",
    },
    {
      field: "rule_severity",
      headerName: "Severity",
      flex: 0.7,
      sortable: false,
      valueGetter: (p) => p?.row?.rule_info?.severity ?? null,
      renderCell: (p) => {
        const s = p?.row?.rule_info?.severity;
        if (!s) return "—";
        if (s === "high")
          return <Chip color="error" label="high" size="small" />;
        if (s === "medium")
          return <Chip color="warning" label="medium" size="small" />;
        return <Chip label={String(s)} size="small" />;
      },
    },

    {
      field: "family",
      headerName: "Family",
      flex: 0.9,
      sortable: false,
      renderCell: (p) => p?.row?.family ?? "—",
    },
    {
      field: "family_conf",
      headerName: "FamConf",
      flex: 0.8,
      sortable: false,
      renderCell: (p) => fmtNum(p?.row?.family_conf, 3),
    },
    {
      field: "gt_attack",
      headerName: "GT (replay)",
      flex: 1.2,
      sortable: false,
      renderCell: (p) => p?.row?.gt_attack ?? "—",
    },
  ];

  return (
    <Box sx={{ height: 600, width: "100%" }}>
      <DataGrid
        rows={safeRows}
        columns={columns}
        getRowId={(r) =>
          `${r.ts ?? 0}-${r.stage ?? "x"}-${r.verdict ?? "x"}-${r.gt_attack ?? ""}`
        }
        pageSizeOptions={[25, 50, 100]}
        initialState={{
          pagination: { paginationModel: { pageSize: 50, page: 0 } },
        }}
        disableRowSelectionOnClick
        onRowClick={(p) => onSelect?.(p.row)}
      />
    </Box>
  );
}
