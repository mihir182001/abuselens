"""FastAPI scoring service: POST /score -> calibrated risk score + top reasons."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .. import config
from ..features.lexical import url_features
from ..models import explain, train

app = FastAPI(title="AbuseLens", version="0.1.0",
              description="Malicious URL risk scoring with explanations.")


class ScoreRequest(BaseModel):
    url: str = Field(min_length=4, max_length=4096)


class Reason(BaseModel):
    feature: str
    value: float | None
    pushes: str
    contribution: float
    description: str


class ScoreResponse(BaseModel):
    url: str
    risk_score: float
    flagged: bool
    threshold: float
    model_trained_at: str | None
    reasons: list[Reason]


@lru_cache(maxsize=1)
def _model(model_dir: str):
    path = Path(model_dir) / "champion"
    if not (path / "bundle.joblib").exists():
        raise FileNotFoundError(f"no champion model at {path}; run `abuselens train`")
    return train.load(path)


@app.get("/health")
def health():
    try:
        _, meta = _model(str(config.MODEL_DIR))
        return {"status": "ok", "model_trained_at": meta.get("trained_at")}
    except FileNotFoundError as e:
        return {"status": "no_model", "detail": str(e)}


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    try:
        bundle, meta = _model(str(config.MODEL_DIR))
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    row = pd.DataFrame([url_features(req.url)])
    for c in bundle["features"]:  # enrichment columns aren't available at request time
        if c not in row:
            row[c] = float("nan")
    p = float(train.score(bundle, row)[0])
    return ScoreResponse(url=req.url, risk_score=round(p, 4), flagged=p >= bundle["threshold"],
                         threshold=round(bundle["threshold"], 4),
                         model_trained_at=meta.get("trained_at"),
                         reasons=explain.top_reasons(bundle, row))
