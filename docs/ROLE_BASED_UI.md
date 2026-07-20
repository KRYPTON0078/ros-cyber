# Role-Based UI

The dashboard adapts actions based on the JWT role:

- `admin` can export reports and seed demo data.
- `operator` can seed demo data but cannot export reports.
- `guest` has read-only panels and no actions enabled.
