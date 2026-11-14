# RFCs — Helios design records

This directory holds Request for Comments (RFC) documents for anything new in
Helios: a kernel object, an ABI change, a research bet, or a new server. No
code for it may be written before the RFC is accepted (PLAN.md section 10.2).

## Process (PLAN.md 10.2)

1. **Read.** Find the relevant entries in `docs/research/BIBLIOGRAPHY.md` and
   cite them by ID. Add any new source you rely on, following the entry format.
2. **Write an RFC** using `docs/rfcs/0000-template.md`. Number it with the next
   free `NNNN-` prefix.
3. **Get acceptance.** The coordinator (NV) accepts an RFC that changes a
   syscall, the IPC wire format, a HAL trait, or a milestone. An RFC that
   touches only the owner's own area and no interface may be self-accepted. An
   accepted RFC becomes an ADR in `docs/DECISIONS.md`.
4. **Specify before coding:** the Verus spec, TLA+ model or Kani harness comes
   first, in the same task or the task before.
5. **Build behind a feature flag** until the exit test passes, then measure
   with `bench/` and record the result in the ADR.

## Naming

Files are named `docs/rfcs/NNNN-title.md` with a zero-padded four-digit number
and a short kebab-case title, e.g. `docs/rfcs/0001-object-model-v2.md`.

## Acceptance rules

- Only the coordinator (`[NV]`) accepts an RFC that changes a syscall, the IPC
  wire format, a HAL trait, or a milestone. Acceptance is recorded by appending
  an `## ADR-NNNN acceptance` entry to `docs/DECISIONS.md` — never by editing
  an existing ADR.
- A worker may self-accept an RFC that affects only its own directories and no
  interface.
- `docs/DECISIONS.md` is append-only; never edit above the end of the file.
