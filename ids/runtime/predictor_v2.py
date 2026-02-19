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
        hit = run_rules(flow)

        rule_info = None
        if hit is not None:
            rule_info = {
                "rule": hit.name,
                "severity": hit.severity,
                "score": float(hit.score),
                "reason": hit.reason,
            }

        # High-confidence rule: chặn luôn
        if hit is not None and hit.severity == "high":
            return {
                "p_attack": None,
                "stage": "rule",
                "verdict": "attack",
                "family": None,
                "family_conf": None,
                "rule_info": rule_info,   # <-- QUAN TRỌNG
            }

        # Binary
        xb = self._vectorize(flow, self.bin_feats).reshape(1, -1)
        xb = self.scb.transform(xb).astype(np.float32, copy=False)
        tb = torch.from_numpy(xb).to(self.device)
        p_attack = torch.sigmoid(self.mb(tb)).item()

        out = {
            "p_attack": float(p_attack),
            "stage": "binary",
            "verdict": None,
            "family": None,
            "family_conf": None,
            "rule_info": rule_info,      # <-- attach cả medium/none
        }

        if p_attack < self.tau_low:
            out["verdict"] = "benign"
            return out

        if p_attack <= self.tau_high:
            out["verdict"] = "suspicious"
            return out

        # Family
        xf = self._vectorize(flow, self.fam_feats).reshape(1, -1)
        xf = self.scf.transform(xf).astype(np.float32, copy=False)
        tf = torch.from_numpy(xf).to(self.device)
        probs = torch.softmax(self.mf(tf), dim=1).cpu().numpy()[0]
        idx = int(probs.argmax())

        out["stage"] = "family"
        out["verdict"] = "attack"
        out["family"] = str(self.le.inverse_transform([idx])[0])
        out["family_conf"] = float(probs[idx])
        return out

    