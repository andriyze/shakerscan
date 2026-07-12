# Bounded Research Agent

Use the `research-agent` skill to create or continue a target-bound ShakerScan research episode.

**Usage:** `/research <target-id-or-episode-id> [objective]`

If the first argument is a target ID, create a read-only episode and report its ID. If it is an episode ID, fetch the current observation and act as the planner for one decision at a time through `/research/episodes/{id}/decisions`. Use only proposable commands and keep execution inside ShakerScan. Ask before creating a gated episode and require the necessary scope and approval receipts.

