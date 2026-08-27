# Database Operation Labels Design

## Goal

Replace the database package's built-in `"db.*"` operation literals with one
closed, typed vocabulary while preserving caller-defined labels such as
`"orders.place"`.

## Design

Add a public `DatabaseOperation(StrEnum)` in a focused `operations.py` module.
It contains exactly these members:

- `STATEMENT = "db.statement"`
- `SESSION = "db.session"`
- `READER_SESSION = "db.reader_session"`
- `TRANSACTION = "db.transaction"`
- `INITIALIZE = "db.initialize"`
- `INITIALIZE_READER = "db.initialize.reader"`
- `HEALTH = "db.health"`
- `HEALTH_READER = "db.health.reader"`

All package-owned call sites use enum members. `DatabaseOperation` is exported
from `hypervigilant.db` so consumers can use the same labels in assertions,
instrumentation, and adapters.

Public `operation` parameters remain typed as `str`. They intentionally accept
application-specific labels, and `StrEnum` members satisfy that contract
without conversion at call sites. `DatabaseError` normalizes the stored
operation to a plain string at its output boundary. Health reports likewise
render the enum value through normal string formatting.

## Boundaries

The enum owns only package-defined observability labels. It does not replace
domain labels, add operation-based dispatch, or change retry/error
classification. No compatibility shim or duplicate string constants are
introduced.

## Testing

- Assert the enum is a closed eight-member `StrEnum` with the exact stable
  values above.
- Assert `DatabaseOperation` is part of the public database API.
- Update operation assertions to use enum members.
- Verify translated errors still expose plain strings.
- Run Ruff, mypy, pyright, and the complete test suite.
