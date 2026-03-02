# Example drop-ins for genpolicy settings

Copy the drop-in file(s) you need into your `genpolicy-settings.d/` directory, then run `genpolicy -j <path-to-that-directory>`.

Each drop-in is an [RFC 6902 JSON Patch](https://datatracker.ietf.org/doc/html/rfc6902): a JSON array of operations (`add`, `remove`, `replace`, `move`, `copy`, `test`). Use `replace` for existing paths, `add` for new keys or array append (path ending in `/-`), and optional `test` to assert values before changing them.

| Drop-in file | Use case |
|--------------|----------|
| `10-non-coco-drop-in.json` | Non-CoCo guest (e.g. standard VMs) |
| `10-non-coco-aks-drop-in.json` | Non-CoCo on AKS |
| `10-non-coco-aks-cbl-mariner-drop-in.json` | Non-CoCo on AKS with CBL-Mariner host |
| `10-oci-1.2.0-drop-in.json` | OCI bundle version 1.2.0 |
| `10-oci-1.2.1-drop-in.json` | OCI bundle version 1.2.1 |
| `10-oci-1.3.0-drop-in.json` | OCI bundle version 1.3.0 |
| `10-experimental-force-guest-pull-drop-in.json` | Disable guest pull (e.g. when using experimental-force-guest-pull) |

Request/exec overrides (e.g. allowing `kubectl exec` or specific ttrpc requests) are not shipped as drop-in examples; build your own drop-in or merge the needed `request_defaults` into a local file in `genpolicy-settings.d/`.
