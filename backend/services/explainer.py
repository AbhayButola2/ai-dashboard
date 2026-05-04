"""
services/explainer.py
----------------------
Phase 7: SHAP explainability for the existing RandomForest classifier.

Provides:
  - explain_record(record) → feature importance dict + human-readable string
  - explain_batch(records) → list of explanations
"""
import logging
import numpy as np
import pandas as pd

logger = logging.getLogger("explainer")

_shap_available = False
try:
    import shap
    _shap_available = True
except ImportError:
    pass


def _make_explanation_string(feature_scores: dict, severity: str) -> str:
    """Convert SHAP scores to a human-readable sentence."""
    if not feature_scores:
        return f"Classified as {severity}."

    top = sorted(feature_scores.items(), key=lambda x: abs(x[1]), reverse=True)[:2]
    reasons = []
    for feat, val in top:
        if feat == "threat_type_enc":
            reasons.append("known malicious threat type")
        elif feat == "tags_count":
            reasons.append("high tag count" if val > 0 else "low tag count")
        elif feat == "source_enc":
            reasons.append("URLhaus source (high reputation)" if val > 0 else "non-URLhaus source")
    reason_str = " and ".join(reasons) if reasons else "feature pattern"
    return f"{severity} severity because of {reason_str}."


def explain_record(record: dict) -> dict:
    """
    Run SHAP TreeExplainer on one log record.
    Returns {feature_importances, explanation_string, predicted_severity}
    """
    from models.ml_classifier import classifier

    row = pd.DataFrame([record])
    features = classifier.extract_features(row)

    predicted = classifier.predict(row)
    severity  = predicted[0] if predicted else record.get("severity", "Unknown")

    if not _shap_available:
        return {
            "predicted_severity": severity,
            "feature_importances": {},
            "explanation": f"{severity} severity (SHAP not installed).",
        }

    try:
        explainer   = shap.TreeExplainer(classifier.model)
        shap_values = explainer.shap_values(features)

        feature_names = list(features.columns)
        # For multi-class RF, shap_values is a list; pick the predicted class index
        classes = list(classifier.model.classes_)
        sev_idx = classes.index(severity) if severity in classes else 0

        if isinstance(shap_values, list):
            vals = shap_values[sev_idx][0]
        else:
            vals = shap_values[0]

        feat_scores = {name: float(val) for name, val in zip(feature_names, vals)}
        explanation = _make_explanation_string(feat_scores, severity)

        return {
            "predicted_severity":  severity,
            "feature_importances": feat_scores,
            "explanation":         explanation,
        }
    except Exception as e:
        logger.error(f"SHAP explain failed: {e}")
        return {
            "predicted_severity": severity,
            "feature_importances": {},
            "explanation": f"{severity} severity (SHAP error: {e}).",
        }


def explain_batch(records: list) -> list:
    """Run explain_record on each record; returns list of explanation dicts."""
    results = []
    for rec in records:
        try:
            exp = explain_record(rec)
            exp["log_id"] = rec.get("id", "")
            results.append(exp)
        except Exception as e:
            results.append({"log_id": rec.get("id", ""), "error": str(e)})
    return results
