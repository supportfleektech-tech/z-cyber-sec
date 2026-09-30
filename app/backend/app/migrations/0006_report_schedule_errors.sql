-- SEC-098: a report schedule whose build failed was retried on every scheduler
-- tick (default: every 30s) forever, with nothing recorded anywhere — no audit,
-- no error on the row, and `run-due` reporting only `built: 0`. The failure was
-- therefore indistinguishable from "nothing was due". Track it on the row itself:
-- `failures` counts consecutive failures (reset on success), `last_error` holds the
-- reason, and both are cleared once a run succeeds.
ALTER TABLE report_schedules ADD COLUMN failures   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE report_schedules ADD COLUMN last_error TEXT;
