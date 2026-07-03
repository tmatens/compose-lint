# postgres — validation criteria (fixture)

Representative workload: `profiles/workloads/postgres.sh` (connect + CRUD + reload).

## capabilities
- Pass criteria: the workload succeeds with only the derived `cap_add`; no denied
  capability check for a dropped cap.
