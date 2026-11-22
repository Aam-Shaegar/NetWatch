"""Estimators for source-held-out research training on traffic-v3 windows."""

from collections import Counter, defaultdict

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, Normalizer, StandardScaler

from .model import COLUMNS, TYPES

FIND_RECIPES = ("raw_rf", "structure_rf", "structure_gb", "structure_lr")
TYPE_RECIPES = (*FIND_RECIPES, "exposure_rf", "exposure_gb", "exposure_lr", "protocol_lr")
FAMILY = {"rf": "random_forest", "gb": "gradient_boosting", "lr": "logistic_regression"}
RELATIVE_FEATURES = (
    ("protocol_packets", ("in_packets", "in_udp_packets", "in_icmp_packets")),
    ("protocol_bytes", ("in_ip_bytes", "in_udp_ip_bytes", "in_icmp_ip_bytes")),
    ("direction", ("in_packets", "out_packets")),
    ("byte_direction", ("in_ip_bytes", "out_ip_bytes")),
    ("tcp_outcomes", ("new_tcp_attempts", "established_tcp_attempts")),
    ("tcp_concentration", ("in_tcp_distinct_ports_per_source_max", "unique_destination_ports")),
    ("ports_to_flows", ("unique_destination_ports", "active_flows")),
    ("ports_to_peers", ("in_tcp_distinct_ports_per_source_max", "unique_peers")),
)
PROTOCOL_COLUMNS = (
    "in_tcp_distinct_ports_per_source_max", "new_tcp_attempts",
    "in_udp_packets", "in_icmp_packets", "syn_fraction", "rst_fraction",
)


def make_candidate(recipe, seed):
    algorithm = recipe.rsplit("_", 1)[1]
    if algorithm == "rf":
        estimator = RandomForestClassifier(
            n_estimators=90, max_features=0.75, min_samples_leaf=2, max_depth=14,
            n_jobs=2, random_state=seed,
        )
    elif algorithm == "gb":
        estimator = HistGradientBoostingClassifier(
            max_iter=90, max_leaf_nodes=15, l2_regularization=2.,
            min_samples_leaf=8, early_stopping=False, random_state=seed,
        )
    elif algorithm == "lr":
        estimator = LogisticRegression(C=0.7, max_iter=400, random_state=seed)
    else:
        raise ValueError(f"unknown research estimator: {recipe}")
    steps = [("impute", SimpleImputer(strategy="constant", fill_value=0., keep_empty_features=True))]
    if recipe != "raw_rf":
        selected = PROTOCOL_COLUMNS if recipe == "protocol_lr" else COLUMNS
        columns = [("levels", FunctionTransformer(np.log1p), [COLUMNS.index(key) for key in selected])]
        for name, group in RELATIVE_FEATURES:
            columns.append((name, Normalizer(norm="l1"), [COLUMNS.index(key) for key in group]))
        steps.append(("shape", ColumnTransformer(columns)))
    if algorithm == "lr":
        steps.append(("scale", StandardScaler()))
    steps.append(("estimator", estimator))
    return Pipeline(steps)


def balanced_sample(rows, labels, indices, cap, seed):
    """Allocate equal mass to each class, source within class, and episode within source."""
    blocks = defaultdict(list)
    for index in indices:
        row = rows[index]
        episode = row.get("episode") or row["capture"]
        blocks[(labels[index], row["source"], episode, row["group"])].append(index)
    sources = defaultdict(set)
    episodes = Counter()
    for label, source, _, _ in blocks:
        sources[label].add(source)
        episodes[label, source] += 1
    rng = np.random.default_rng(seed)
    selected = []
    weights = []
    for (label, source, _, _), block in sorted(blocks.items()):
        if len(block) > cap:
            block = sorted(rng.choice(block, cap, replace=False).tolist())
        mass = 1 / (len(sources) * len(sources[label]) * episodes[label, source])
        selected.extend(block)
        weights.extend([mass / len(block)] * len(block))
    return np.asarray(selected, dtype=int), np.asarray(weights)


def fit_candidate(recipe, stage, rows, values, labels, training, seed):
    known = np.isin(labels, TYPES)
    include = known | (labels == "normal") if stage == "find" else known
    idx, weights = balanced_sample(rows, labels, np.flatnonzero(training & include), 480, seed)
    x = values[idx]
    y = labels[idx]
    scale = len(weights)
    if stage == "find":
        weights = np.where(y == "normal", weights * len(TYPES), weights)
        y = (y != "normal").astype(int)
    elif recipe.startswith("exposure_"):
        # A verified normal observation has no catalogue type. Giving it equal
        # target mass for each type discourages confident predictions off support.
        # Unknown-family examples remain reserved for threshold calibration.
        normal, background_weights = balanced_sample(
            rows, labels, np.flatnonzero(training & (labels == "normal")), 100, seed,
        )
        background = values[normal]
        x = np.concatenate([x, *[background for _ in TYPES]])
        y = np.concatenate([y, *[np.full(len(normal), label) for label in TYPES]])
        weights = np.concatenate([weights, *[background_weights * 0.60 / len(TYPES) for _ in TYPES]])
    weights = weights * (scale / weights.sum())
    model = make_candidate(recipe, seed)
    model.fit(x, y, estimator__sample_weight=weights)
    return model
