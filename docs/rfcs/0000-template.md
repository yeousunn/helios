## RFC-NNNN: <title>

- Proposed: <TAG> <date>
- Status: PROPOSED | ACCEPTED | SELF-ACCEPTED | REJECTED | SUPERSEDED by RFC-MMMM
- Links: cites `docs/research/BIBLIOGRAPHY.md` entries by ID (e.g. [R-SEL4])

### Problem

One paragraph on what is missing or broken, and why the current design cannot
fix it. State which design principle(s) from PLAN.md section 2 it serves, and
which principle (if any) it breaks and why.

### Research basis

The bibliography IDs this design draws on ([R-SEL4], [R-NROS], ...). Summarize
the relevant result from each cited source.

### Design

The object/ABI/bet's state machine, invariants, and the kernel/userspace
interaction. Include a small state-transition description and the failure
modes. Every new kernel object needs: an RFC state machine, a Verus
specification, validation ranges for every argument, and a commutativity
statement (PLAN.md section 4.1).

### ABI

For each new or changed syscall/invoke argument:
- the allowed range,
- the error returned when out of range,
- whether the operation commutes with others (and on what resources).

An ABI change also needs the `spec/abi` update, validation ranges, a
commutativity note, and attack-suite cases (PLAN.md section 8.3).

### Verification plan

Which tool covers what: Verus specification/proof, Flux index bounds, Kani
panic-freedom or `unsafe` contract harnesses, TLA+ model, host unit tests,
attack-suite cases.

### Benchmark and success metric

Which `bench/` benchmark measures it, the target number, and how success is
judged.

### Kill criterion

The condition under which this bet is dropped and what ships as the fallback.

### Alternatives considered

Other designs that were rejected and why.
