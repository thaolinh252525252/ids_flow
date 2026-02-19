import {
  Box,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  Divider,
  Stack,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";

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

export default function AlertDetailDialog({ item, onClose }) {
  const open = !!item;

  const rule = item?.rule_info?.rule ?? null;
  const severity = item?.rule_info?.severity ?? null;
  const reason = item?.rule_info?.reason ?? null;
  const score = item?.rule_info?.score ?? null;

  const verdict = item?.verdict ?? "unknown";
  const stage = item?.stage ?? "binary";

  const verdictChip =
    verdict === "attack" ? (
      <Chip color="error" label="attack" />
    ) : verdict === "suspicious" ? (
      <Chip color="warning" label="suspicious" />
    ) : (
      <Chip label={verdict} />
    );

  const sevChip =
    severity === "high" ? (
      <Chip color="error" size="small" label="high" />
    ) : severity === "medium" ? (
      <Chip color="warning" size="small" label="medium" />
    ) : (
      <Chip size="small" label="none" />
    );

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ fontWeight: 900 }}>
        Alert detail
        <Typography variant="body2" sx={{ opacity: 0.7, mt: 0.5 }}>
          {fmtTs(item?.ts)}
        </Typography>
      </DialogTitle>

      <DialogContent>
        <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", mb: 1.5 }}>
          {verdictChip}
          <Chip label={`stage: ${stage}`} />
          {rule ? <Chip label={`rule: ${rule}`} /> : null}
          {rule ? sevChip : null}
        </Stack>

        <Divider sx={{ mb: 1.5 }} />

        <Box sx={{ display: "grid", gap: 1 }}>
          <Row k="p_attack" v={fmtNum(item?.p_attack, 4)} />
          <Row
            k="family"
            v={
              item?.family
                ? `${item.family} (conf: ${fmtNum(item.family_conf, 3)})`
                : "—"
            }
          />
          <Row k="GT (replay)" v={item?.gt_attack ?? "—"} />
          {rule ? <Row k="rule score" v={fmtNum(score, 2)} /> : null}
          {rule ? <Row k="reason" v={reason ?? "—"} /> : null}
        </Box>

        <Accordion sx={{ mt: 2 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ fontWeight: 800 }}>Raw JSON</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
              {JSON.stringify(item, null, 2)}
            </pre>
          </AccordionDetails>
        </Accordion>
      </DialogContent>
    </Dialog>
  );
}

function Row({ k, v }) {
  return (
    <Box sx={{ display: "flex", justifyContent: "space-between", gap: 2 }}>
      <Typography variant="body2" sx={{ opacity: 0.7 }}>
        {k}
      </Typography>
      <Typography variant="body2" sx={{ fontWeight: 800, textAlign: "right" }}>
        {v}
      </Typography>
    </Box>
  );
}
