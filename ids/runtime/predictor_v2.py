import json
import numpy as np
import torch
import torch.nn as nn
import joblib
from ids.runtime.rules_v2 import run_rules

class MLPBinary(nn.Module):
    def __init__(self, in_dim, h1=256, h2=128, dropout=0.2):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, h1), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(h1, h2), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(h2, 1),
        )
    def forward(self, x):
        return self.net(x).squeeze(1)

class MLPFamily(nn.Module):
    def __init__(self, in_dim, num_classes, h1=256, h2=128, dropout=0.2):
        super().__init__()
        self.fc1 = nn.Linear(in_dim, h1)
        self.fc2 = nn.Linear(h1, h2)
        self.out = nn.Linear(h2, num_classes)
        self.drop = nn.Dropout(dropout)
        self.act = nn.ReLU()
    def forward(self, x):
        x = self.drop(self.act(self.fc1(x)))
        x = self.drop(self.act(self.fc2(x)))
        return self.out(x)

class IDSRuntimeV2:
    def __init__(
        self,
        binary_schema="schemas/v2/binary.json",
        binary_scaler="artifacts/v2/binary/scaler.pkl",
        binary_model="artifacts/v2/binary/model.pt",
        family_schema="schemas/v2/family.json",
        family_scaler="artifacts/v2/family/scaler.pkl",
        family_model="artifacts/v2/family/model.pt",
        label_encoder="datasets/v2/family/label_encoder.pkl",
        tau_low=0.2,
        tau_high=0.95,
        device=None,
    ):
        self.tau_low = float(tau_low)
        self.tau_high = float(tau_high)

        self.bin_feats = json.load(open(binary_schema))["feature_names"]
        self.fam_feats = json.load(open(family_schema))["feature_names"]

        self.scb = joblib.load(binary_scaler)
        self.scf = joblib.load(family_scaler)
        self.le  = joblib.load(label_encoder)

        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = torch.device(device)

        ck_b = torch.load(binary_model, map_location="cpu")
        self.mb = MLPBinary(in_dim=ck_b["in_dim"]).to(self.device)
        self.mb.load_state_dict(ck_b["model_state_dict"])
        self.mb.eval()

        ck_f = torch.load(family_model, map_location="cpu")
        self.mf = MLPFamily(in_dim=ck_f["in_dim"], num_classes=ck_f["num_classes"]).to(self.device)
        self.mf.load_state_dict(ck_f["model_state_dict"])
        self.mf.eval()

    def _vectorize(self, flow: dict, feats: list[str]) -> np.ndarray:
        # ensure order + missing -> 0
        x = np.array([float(flow.get(k, 0.0) or 0.0) for k in feats], dtype=np.float32)
        return x

    # @torch.no_grad()
    # def predict_flow(self, flow: dict) -> dict:
    #     hit = run_rules(flow)
        
    #     if hit and hit.severity == "high":
    #         return {
    #             "p_attack": None,
    #             "stage": "rule",
    #             "verdict": "attack",
    #             "rule": hit.name,
    #             "rule_score": hit.score,
    #             "rule_reason": hit.reason,
    #             "family": None,
    #             "family_conf": None,
    #         }


    #     xb = self._vectorize(flow, self.bin_feats).reshape(1, -1)
    #     xb = self.scb.transform(xb).astype(np.float32, copy=False)

    #     tb = torch.from_numpy(xb).to(self.device)
    #     p_attack = torch.sigmoid(self.mb(tb)).item()

    #     hit = run_rules(flow)
    #     rule_info = None
    #     if hit:
    #         rule_info = {"rule": hit.name, "rule_score": hit.score, "rule_reason": hit.reason, "rule_severity": hit.severity}

    #     out = {
    #         "p_attack": float(p_attack),
    #         "stage": "binary",
    #         "verdict": None,
    #         "family": None,
    #         "family_conf": None,
    #         "rule_info": rule_info,
    #     }


    #     if p_attack < self.tau_low:
    #         out["verdict"] = "benign"
    #         return out

    #     if p_attack <= self.tau_high:
    #         out["verdict"] = "suspicious"
    #         return out

    #     # high confidence attack -> family
    #     xf = self._vectorize(flow, self.fam_feats).reshape(1, -1)
    #     xf = self.scf.transform(xf).astype(np.float32, copy=False)
    #     tf = torch.from_numpy(xf).to(self.device)
    #     probs = torch.softmax(self.mf(tf), dim=1).cpu().numpy()[0]
    #     idx = int(probs.argmax())
    #     out["stage"] = "family"
    #     out["verdict"] = "attack"
    #     out["family"] = str(self.le.inverse_transform([idx])[0])
    #     out["family_conf"] = float(probs[idx])
    #     return out
    ###################################
    @torch.no_grad()
    def predict_flow(self, flow: dict) -> dict:
        # -------- Rule (always run) --------
        hit = run_rules(flow)
        rule_result = None
        if hit is not None:
            rule_result = {
                "hit": True,
                "name": hit.name,
                "severity": hit.severity,
                "score": float(hit.score),
                "reason": hit.reason,
            }
        else:
            rule_result = {"hit": False}

        # -------- ML Binary (always run) --------
        xb = self._vectorize(flow, self.bin_feats).reshape(1, -1)
        xb = self.scb.transform(xb).astype(np.float32, copy=False)
        tb = torch.from_numpy(xb).to(self.device)
        p_attack = float(torch.sigmoid(self.mb(tb)).item())

        if p_attack < self.tau_low:
            ml_verdict = "benign"
        elif p_attack < self.tau_high:
            ml_verdict = "suspicious"
        else:
            ml_verdict = "attack"

        ml_binary = {
            "p_attack": p_attack,
            "verdict": ml_verdict,
            "tau_low": float(self.tau_low),
            "tau_high": float(self.tau_high),
        }

        # -------- ML Family (only if attack) --------
        family_name, family_conf = None, None
        if ml_verdict == "attack":
            xf = self._vectorize(flow, self.fam_feats).reshape(1, -1)
            xf = self.scf.transform(xf).astype(np.float32, copy=False)
            tf = torch.from_numpy(xf).to(self.device)
            probs = torch.softmax(self.mf(tf), dim=1).cpu().numpy()[0]
            idx = int(probs.argmax())
            family_name = str(self.le.inverse_transform([idx])[0])
            family_conf = float(probs[idx])

        ml_family = {"name": family_name, "conf": family_conf}

        # -------- Final decision (combine) --------
        # High rule = strong override to attack
        rule_high = (hit is not None and hit.severity == "high")
        rule_any = (hit is not None)

        if rule_high:
            final_verdict = "attack"
            final_source = "both" if ml_verdict == "attack" else "rule-only"
            final_stage = "rule"
        else:
            if rule_any and ml_verdict in ("suspicious", "attack"):
                final_verdict = ml_verdict
                final_source = "both"
                final_stage = "family" if (ml_verdict == "attack" and family_name is not None) else "binary"
            elif rule_any:
                # medium rule only -> suspicious (dễ giải thích demo)
                final_verdict = "suspicious" if hit.severity == "medium" else "suspicious"
                final_source = "rule-only"
                final_stage = "rule"
            else:
                final_verdict = ml_verdict
                final_source = "ml-only" if ml_verdict != "benign" else "none"
                final_stage = "family" if (ml_verdict == "attack" and family_name is not None) else "binary"

        # -------- Backward-compatible output fields (UI/charts cũ vẫn chạy) --------
        out = {
            # legacy fields
            "p_attack": p_attack,
            "stage": final_stage,
            "verdict": final_verdict,
            "family": family_name if final_verdict == "attack" else None,
            "family_conf": family_conf if final_verdict == "attack" else None,

            # keep your old rule_info shape too (so existing UI doesn’t break)
            "rule_info": None if hit is None else {
                "rule": hit.name,
                "severity": hit.severity,
                "score": float(hit.score),
                "reason": hit.reason,
            },

            # NEW: separated signals (Policy 1)
            "rule_result": rule_result,
            "ml_binary": ml_binary,
            "ml_family": ml_family,
            "final_source": final_source,
            "ml_verdict": ml_verdict,  # convenient for UI
        }
        return out