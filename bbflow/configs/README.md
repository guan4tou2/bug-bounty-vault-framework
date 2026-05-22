# bbflow Config Examples

These files are public-safe configuration shapes for connecting common recon tools to a private bbflow runtime.

They are not operational playbooks. Bring your own runtime, install tools in a private environment, and adapt the examples to your authorized scope.

The contract is intentionally bring your own runtime: this public repository describes boundaries, not an installed scanner stack.

Included shapes:

- `nuclei.profile.example.yaml` for Nuclei template selection boundaries.
- `osmedeus.profile.example.yaml` for Osmedeus workflow stage boundaries.
- `bbot.profile.example.yaml` for BBOT module and output boundaries.

Rules:

- Keep authorized scope as the input contract.
- Keep raw output in the ignored `workspace/` runtime area.
- Keep generated candidates machine-readable.
- Promote only reviewed, sanitized lessons back into the vault.
- Do not add payloads, evasion guidance, secrets, target-specific templates, or private findings to this public repository.
