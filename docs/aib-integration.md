# AIB Integration — Asset-Enriched Alert Analysis

> **Optional Feature**: Requires [Assets in a Box (AIB)](https://github.com/matijazezelj/aib) running and accessible from the SIB analysis container.

## What Is AIB?

Assets in a Box (AIB) is a graph-based asset inventory. It models your infrastructure as a graph of nodes (Kubernetes pods, VMs, hosts, services) with relationships between them — ownership, network adjacency, dependency chains.

Each node carries:
- **Metadata** — environment, team, owner, criticality, service name
- **Blast radius** — which downstream assets are reachable if this node is compromised
- **Audit findings** — pre-existing security findings from previous scans

## What the Integration Does

Without AIB, SIB analyzes Falco alerts purely from the event payload — process name, syscall, file path, priority. The LLM has no idea *what* the affected asset is, who owns it, or what it connects to.

With AIB, before the alert reaches the LLM:

1. **Asset lookup** — SIB extracts the container name + namespace (for Kubernetes) or hostname (for VMs) from the Falco alert and resolves the corresponding AIB node
2. **Blast radius fetch** — how many downstream assets are reachable if this node is compromised
3. **Audit findings fetch** — any pre-existing findings on this asset (misconfigurations, CVEs, compliance gaps)
4. **Prompt injection** — all of this is appended to the LLM prompt as structured context

The result: the LLM can reason about *actual impact*, not just the raw event. A `Read sensitive file` alert on an internet-facing payment service that has 12 downstream dependencies hits differently than the same alert on an internal dev sandbox.

## Data Flow

```
Falco alert
    │
    ▼
AlertAnalyzer.analyze_alert()
    │
    ├─► AIBClient.enrich_alert()
    │       │
    │       ├─ container.name + namespace → k8s:pod:<ns>/<name>
    │       │   └─ fallback: host.hostname → vm:host:<hostname>
    │       │                              → k8s:node:<hostname>
    │       │
    │       ├─ GET /api/v1/graph/nodes/{node_id}        → asset metadata
    │       ├─ GET /api/v1/impact/{node_id}              → blast radius
    │       └─ GET /api/v1/graph/analysis/audit?node_id= → audit findings
    │
    ├─► Obfuscator (IPs, usernames, paths → tokens)
    │
    ├─► LLM prompt (alert + AIB context section)
    │
    └─► Analysis result (with aib_context field)
```

## Node ID Format

AIB uses a `source:type:identifier` format for node IDs:

| Asset type | Node ID format | Falco fields used |
|------------|---------------|-------------------|
| Kubernetes pod | `k8s:pod:<namespace>/<pod-name>` | `container.name` + `kubernetes.namespace.name` |
| VM / bare-metal host | `vm:host:<hostname>` | `host.hostname` |
| Kubernetes node | `k8s:node:<nodename>` | `host.hostname` (fallback) |

The bridge tries K8s pod first. If the container name is empty, `host`, or `<NA>`, it falls back to hostname-based lookups.

## Configuration

### 1. Set environment variables

In your `.env` file:

```bash
AIB_BASE_URL=http://aib:8080       # AIB API endpoint (Docker service name or IP)
AIB_API_TOKEN=your-aib-api-token   # Optional — omit if AIB has no auth
```

### 2. Verify `config.yaml`

The `aib` block is already present after `make install-analysis`:

```yaml
aib:
  url: ${AIB_BASE_URL:-}       # leave empty to disable
  api_token: ${AIB_API_TOKEN:-}
  cache_ttl: 300               # seconds — AIB responses are cached per node
```

### 3. Restart the analysis service

```bash
make restart-analysis
```

### Disabling AIB

Leave `AIB_BASE_URL` empty (or unset). The integration is fully opt-in — if the URL is not configured, no enrichment is attempted and no errors are raised.

## Graceful Degradation

AIB enrichment is best-effort at every step:

- **AIB URL not set** → enrichment skipped, alert analyzed normally
- **AIB unreachable** → exception caught, empty context, analysis proceeds
- **Node not found in AIB (404)** → null context returned, analysis proceeds
- **Partial data** (node found, blast radius unavailable) → whatever is available is included

The LLM prompt is constructed only from the fields that are actually populated. A missing blast radius or missing audit findings simply means that section is omitted from the prompt.

## Example Enriched Analysis

Given a Falco alert:
```
Read sensitive file untrusted: user=appuser file=/etc/shadow
container=payment-api namespace=production host=k8s-node-3
```

The AIB bridge resolves `k8s:pod:production/payment-api` and fetches:

```
Asset Context (AIB graph):
- Asset ID: k8s:pod:production/payment-api
- Environment: production
- Team: payments
- Criticality: critical
- Owner: payments-eng@company.com
- Blast radius: 8 downstream assets
  - k8s:pod:production/fraud-detection
  - k8s:pod:production/billing-service
  - k8s:pod:production/audit-logger
- Pre-existing audit findings (2):
  - Container running as root (CIS 5.4.1)
  - Privileged port binding enabled
```

The LLM now answers with awareness of criticality and blast radius:

```
Risk Assessment: CRITICAL
The affected service (payment-api) is classified as critical infrastructure
in the payments team. Compromise of this pod provides a foothold into 8
downstream services including fraud detection and billing. Combined with
the pre-existing finding that this container runs as root, the attacker
likely already has unrestricted access to the container filesystem.

Immediate actions:
1. Isolate payment-api pod — network policy to deny egress immediately
2. The audit finding "container running as root" amplifies this alert's
   severity — /etc/shadow is accessible without privilege escalation
3. Notify payments-eng team lead — this is a production critical-path service
```

Compare to the same alert without AIB enrichment, where the LLM would give generic advice with no knowledge of production impact.

## API Response

The `/api/analyze` JSON response includes an `aib_context` field:

```json
{
  "rule": "Read sensitive file untrusted",
  "analysis": "...",
  "aib_context": {
    "node_id": "k8s:pod:production/payment-api",
    "node": {
      "id": "k8s:pod:production/payment-api",
      "metadata": {
        "environment": "production",
        "team": "payments",
        "criticality": "critical"
      }
    },
    "blast_radius": {
      "affected_nodes": [...]
    },
    "audit_findings": [
      { "title": "Container running as root", "severity": "high" }
    ]
  }
}
```

`aib_context` is `{}` when AIB is not configured or the asset wasn't found.

## Caching

AIB responses are cached in memory per `cache_ttl` seconds (default: 300s / 5 minutes). This means:

- Repeated alerts from the same pod/host reuse the cached node metadata
- Blast radius and audit findings are not re-fetched on every alert
- Cache is per-process — restarts clear it

For high-volume environments, increase `cache_ttl` to reduce AIB API load. For incident response where asset state is changing rapidly, set it lower or restart the analysis service to force a refresh.
