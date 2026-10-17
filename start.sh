#!/bin/sh
# Fattah AgentGuard — container entrypoint.
# Starts the dashboard, then replays the agent activity stream through the
# pipeline (detection -> triage -> Mini SOAR) so alerts appear live.
set -e

echo "=============================================================="
echo " Fattah AgentGuard"
echo " Dashboard:  http://localhost:${PORT:-8080}"
echo "=============================================================="

python dashboard.py &
DASH_PID=$!
sleep 2

echo ""
echo "Streaming coding-agent activity (delay ${STREAM_DELAY:-0.2}s per event)..."
python ingest.py --quiet --delay "${STREAM_DELAY:-0.2}"

echo ""
echo "Evidence integrity:"
python mini_soar.py --verify

echo ""
echo "Lab validation against ground-truth labels:"
python score.py

echo ""
echo "Pipeline finished. Dashboard still running at http://localhost:${PORT:-8080}"
echo "Replay the stream:  docker compose restart     Stop:  Ctrl+C"
wait "$DASH_PID"
