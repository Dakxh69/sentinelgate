"""SentinelGate Operational Security Dashboard.

A read-only Streamlit visualization interface connected to the audit_events table.
Visualizes:
  - Total request volume and allow/block/review decision ratios
  - DLP sensitive category detection breakdowns
  - High-risk source IPs and recent policy enforcement events
  - Temporal event trends

Run:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import os
from datetime import timedelta, datetime

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text


def database_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg://postgres@127.0.0.1:5432/sentinelgate",
    )


@st.cache_resource
def get_engine():
    return create_engine(database_url(), pool_pre_ping=True)


# The dashboard only ever runs SELECTs against audit_events (§40 read-only).

QUERY_COUNTS = text(
    """
    SELECT decision, COUNT(*) AS n
    FROM audit_events
    GROUP BY decision
    """
)

QUERY_RECENT = text(
    """
    SELECT id, timestamp, method, path, decision, risk_score,
           detected_categories, reason, response_status, user_id, role
    FROM audit_events
    ORDER BY id DESC
    LIMIT :n
    """
)

QUERY_OVER_TIME = text(
    """
    SELECT date_trunc('minute', timestamp) AS minute, decision, COUNT(*) AS n
    FROM audit_events
    WHERE timestamp >= NOW() - :window
    GROUP BY 1, 2
    ORDER BY 1
    """
)

QUERY_TOP_CATEGORIES = text(
    """
    SELECT cat AS category, COUNT(*) AS n
    FROM audit_events,
         jsonb_array_elements_text(detected_categories) AS cat
    WHERE detected_categories IS NOT NULL
      AND jsonb_typeof(detected_categories) = 'array'
    GROUP BY cat
    ORDER BY n DESC
    LIMIT 10
    """
)

QUERY_TOP_REASONS = text(
    """
    SELECT reason, decision, COUNT(*) AS n
    FROM audit_events
    WHERE reason IS NOT NULL
    GROUP BY reason, decision
    ORDER BY n DESC
    LIMIT 10
    """
)

QUERY_TOP_USERS = text(
    """
    SELECT user_id, role, COUNT(*) AS blocked
    FROM audit_events
    WHERE decision = 'BLOCK' AND user_id IS NOT NULL
    GROUP BY user_id, role
    ORDER BY blocked DESC
    LIMIT 10
    """
)

QUERY_LATENCY = text(
    """
    SELECT user_id,
           COUNT(*)                                  AS blocked,
           AVG(risk_score)                           AS avg_risk,
           MAX(risk_score)                           AS max_risk
    FROM audit_events
    WHERE decision = 'BLOCK' AND user_id IS NOT NULL
    GROUP BY user_id
    ORDER BY blocked DESC
    LIMIT 10
    """
)


st.set_page_config(page_title="SentinelGate Dashboard", layout="wide")
st.title("SentinelGate — Zero-Trust Gateway Dashboard")
st.caption("Read-only view over audit_events (spec §40). Writes nothing.")

engine = get_engine()
if engine is None:
    st.stop()


@st.cache_data(ttl=2)
def load(url_unused: str) -> dict[str, pd.DataFrame]:
    # cache key includes the URL so a changed DATABASE_URL re-loads
    with engine.connect() as conn:
        return {
            "counts": pd.read_sql(QUERY_COUNTS, conn),
            "recent": pd.read_sql(QUERY_RECENT, conn, params={"n": 50}),
            "over_time": pd.read_sql(
                QUERY_OVER_TIME, conn, params={"window": timedelta(hours=1)}
            ),
            "categories": pd.read_sql(QUERY_TOP_CATEGORIES, conn),
            "reasons": pd.read_sql(QUERY_TOP_REASONS, conn),
            "users": pd.read_sql(QUERY_TOP_USERS, conn),
            "latency": pd.read_sql(QUERY_LATENCY, conn),
        }


try:
    data = load(database_url())
except Exception as exc:  # noqa: BLE001 — surfaced, not hidden
    st.error(f"Cannot read audit_events: {exc}")
    st.info(
        "Hint: point DATABASE_URL at a reachable PostgreSQL with an "
        "audit_events table (backend migrations must be applied, and the "
        "gateway should have produced audit traffic)."
    )
    st.stop()

# ---------------------------------------------------------------- header row
counts = dict(zip(data["counts"]["decision"], data["counts"]["n"]))
total = int(sum(counts.values())) if counts else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total requests", total)
c2.metric("ALLOW", int(counts.get("ALLOW", 0)))
c3.metric("BLOCK", int(counts.get("BLOCK", 0)))
c4.metric("REVIEW", int(counts.get("REVIEW", 0)))
st.markdown(
    "<small>NOTE: 'Total requests' is the count of *audit events*, which is"
    " every security-relevant request (ALLOW / BLOCK / REVIEW), not every"
    " HTTP request the gateway received.</small>",
    unsafe_allow_html=True,
)

# ------------------------------------------------------------- over time
st.subheader("Requests over time (last hour)")
if data["over_time"].empty:
    st.info("No audit events in the last hour.")
else:
    pivoted = data["over_time"].pivot_table(
        index="minute", columns="decision", values="n", fill_value=0
    )
    st.bar_chart(pivoted)

col_c, col_r = st.columns(2)
with col_c:
    st.subheader("Top DLP categories")
    if data["categories"].empty:
        st.info("No DLP detections recorded yet.")
    else:
        st.dataframe(data["categories"], use_container_width=True, hide_index=True)
with col_r:
    st.subheader("Top reasons")
    if data["reasons"].empty:
        st.info("No events with a reason code recorded yet.")
    else:
        st.dataframe(data["reasons"], use_container_width=True, hide_index=True)

col_u, col_l = st.columns(2)
with col_u:
    st.subheader("Top blocked users")
    if data["users"].empty:
        st.info("No blocked requests tied to a user yet.")
    else:
        st.dataframe(data["users"], use_container_width=True, hide_index=True)
with col_l:
    st.subheader("Blocked users — risk profile")
    if data["latency"].empty:
        st.info("No blocked requests tied to a user yet.")
    else:
        st.dataframe(data["latency"], use_container_width=True, hide_index=True)

st.subheader("Latest audit events")
st.dataframe(
    data["recent"].assign(
        detected_categories=data["recent"]["detected_categories"].apply(
            lambda v: ", ".join(v) if isinstance(v, (list, tuple)) else (v or "")
        )
    ),
    use_container_width=True,
    hide_index=True,
)
st.caption(f"Engine: {database_url()}")
