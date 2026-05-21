# WarpNest

WarpNest is a local proxy tool for running multiple authorized Cloudflare WARP connections inside one process and exposing them as a managed proxy pool.

## Language

**WARP Instance**:
A single authorized Cloudflare WARP connection managed by WarpNest. Multiple WARP Instances may exist in one process.
_Avoid_: Node, account, tunnel

**Instance Identity**:
The stable system-generated identifier for a WARP Instance and its persisted WARP Registration. Users may add labels or groups, but the Instance Identity remains the selector target for `id:<instance-id>`.
_Avoid_: User nickname, editable ID

**WARP Registration**:
The authorization record that lets WarpNest create a WARP Instance, equivalent in product meaning to a registration created before a WARP client connects.
_Avoid_: Account creation, signup

**Public WARP Registration**:
A WARP Registration created against Cloudflare's public consumer WARP service. WarpNest supports this public registration mode rather than Zero Trust device enrollment.
_Avoid_: Zero Trust enrollment, team device enrollment

**Public WARP Scope**:
The product boundary where WarpNest supports ordinary public WARP usage and does not provide WARP+, Zero Trust enrollment, or organization-managed features in the initial scope.
_Avoid_: WARP+ support, organization policy support

**WARP Connection**:
The running state of a WARP Instance after its WARP Registration has been accepted and traffic can be carried through Cloudflare WARP.
_Avoid_: Proxy, session

**User-Space Data Plane**:
The in-process path that carries proxied traffic through selected WARP Instances without taking over the host system's global network route.
_Avoid_: System VPN, global tunnel

**WARP Lifecycle**:
The product-level sequence of creating a WARP Registration and establishing a WARP Connection. WarpNest follows the lifecycle semantics of `warp-cli registration new` and `warp-cli connect` without treating any current client internals as domain concepts.
_Avoid_: Protocol clone, warp-cli compatibility

**Registration Lifecycle**:
The conservative management of WARP Registrations over time. WarpNest restores existing registrations first, creates new ones only when needed to reach the Target Serving Size within the Registration Budget, and avoids automatic churn for the sole purpose of changing Exit IPs. Fully automatic Public WARP Registration remains bounded by the Registration Budget.
_Avoid_: Registration farming, IP refresh loop

**Proxy Pool**:
A collection of WARP Instances that WarpNest can select from when serving outbound proxy traffic.
_Avoid_: IP pool, proxy list

**Proxy Endpoint**:
A SOCKS5 or HTTP proxy listener exposed by WarpNest. By default, a Proxy Endpoint routes traffic through the Serving Pool.
_Avoid_: Port, server

**UDP Proxying**:
The ability for a Proxy Endpoint to carry UDP traffic, including DNS, through the selected WARP Instance. UDP Proxying is part of WarpNest's proxy completeness rather than an optional add-on.
_Avoid_: TCP-only proxying, local DNS fallback

**UDP Association**:
A SOCKS5 UDP proxy association bound to one selected WARP Instance for its lifetime.
_Avoid_: UDP session, DNS shortcut

**Proxy DNS Boundary**:
The rule that target-name resolution for proxied traffic must stay inside the selected WARP Instance path rather than using the host system DNS as a shortcut.
_Avoid_: Local DNS fallback, pre-resolved proxy targets

**Instance Selector**:
A client-provided routing hint used at a Proxy Endpoint to choose which WARP Instance should serve a proxy connection. WarpNest accepts the selector through the proxy username for both SOCKS5 and HTTP proxy authentication; supported selector meanings include automatic selection, `id:<instance-id>`, `exit:<ip>`, and `group:<name>`.
_Avoid_: Login username, account name

**Instance Group**:
A user-defined routing collection for WARP Instances. Groups support selector-based traffic separation but do not imply geography, performance, or a guaranteed Exit IP type.
_Avoid_: Region, location, exit class

**Standby Fallback**:
An optional routing behavior where a group selector may use healthy Standby Pool instances when no Serving Pool instance is available for that group. Standby Fallback is disabled by default.
_Avoid_: Automatic duplicate exit use, silent fallback

**Proxy Authentication**:
The credentials used to authorize a client to use a Proxy Endpoint. Initial Proxy Authentication uses a shared secret in the proxy password field, while the proxy username remains available for the Instance Selector.
_Avoid_: Instance selector, WARP identity

**Control Plane**:
The local ways users configure, inspect, and operate WarpNest. The Control Plane includes CLI commands, a configuration file, and a local management API.
_Avoid_: Dashboard, admin UI

**Daemon Mode**:
The foreground service mode that runs Proxy Endpoints, WARP Instances, probes, and the Management API. System service integration may wrap Daemon Mode but is not part of the core runtime contract.
_Avoid_: systemd-only service, background magic

**Configuration File**:
The user-edited declaration of desired WarpNest behavior, including target pool size, listener addresses, authentication, groups, and probe settings.
_Avoid_: State store, registration database

**State Store**:
The local persistent store for WARP Registrations, Pool Restoration data, Last Observed Exit IPs, lifecycle state, and recent operational observations.
_Avoid_: Configuration file, log file

**Management API**:
A local-only API for inspecting state and operating WarpNest. It exists for automation and future UI support, not as a remotely exposed public service.
_Avoid_: Public API, web UI

**Local-First Exposure**:
The default security posture where Proxy Endpoints and the Management API bind only to local interfaces unless the user explicitly configures external exposure with authentication.
_Avoid_: Open proxy, public management

**Linux-First Support**:
The delivery posture where Linux is the first supported operating system while platform-specific concerns remain isolated so macOS and Windows can be added later.
_Avoid_: Linux-only product, full cross-platform promise

**Pool Status**:
The observable state of a Proxy Pool and its WARP Instances, including readiness, pool membership, Exit IP observations, active connection counts, probe times, and recent non-sensitive errors.
_Avoid_: Secret dump, raw registration data

**Private Observability**:
The logging and status boundary where WarpNest reports operational state without exposing WARP Registration secrets or proxy traffic targets by default.
_Avoid_: Access logging by default, raw secret logging

**Pool Scheduling**:
The selection of a Serving Pool instance for a new proxy connection. WarpNest schedules per connection, prefers the healthy instance with the fewest active connections, and uses round-robin only to break ties.
_Avoid_: Request routing, IP rotation

**Connection Binding**:
The rule that a proxy connection or UDP Association stays attached to its selected WARP Instance for its lifetime. Exit IP changes affect future scheduling, not live connection migration.
_Avoid_: Mid-connection rotation, session migration

**Exit IP**:
The public IP address observed by external services for traffic sent through a WARP Instance. Exit IPs are discovered by probing because Cloudflare controls their assignment.
_Avoid_: Static IP, assigned IP

**Last Observed Exit IP**:
The most recently persisted Exit IP observed for a WARP Instance. WarpNest may use it to prefer stable restoration after restart, but it never replaces a fresh Exit Probe.
_Avoid_: Saved IP, fixed IP

**Exit Probe**:
An observation performed through a WARP Instance to discover its current Exit IP. A WARP Instance must have a successful Exit Probe before it can enter the Serving Pool.
_Avoid_: Health check, IP assignment

**Probe Consensus**:
The rule that Exit Probe observations may use multiple external probe endpoints and should only update pool membership when the observed Exit IP is sufficiently consistent.
_Avoid_: Single probe truth, host-side IP check

**Health Check**:
An availability observation that determines whether a WARP Instance can carry proxy traffic. Health Check results decide whether an instance is serviceable, while Exit Probe results decide how it contributes to Exit Diversity.
_Avoid_: Exit probe, ping

**Retry Discipline**:
The failure-handling rule that registration, connection, probing, and health operations retry independently with backoff, jitter, and global concurrency limits. Clear authorization or policy failures stop automatic retry until user action.
_Avoid_: Tight retry loop, infinite registration loop

**Exit Diversity**:
The degree to which active WARP Instances expose distinct Exit IPs. WarpNest seeks exit diversity by probing and selecting instances with different Exit IPs.
_Avoid_: Guaranteed unique IPs

**Serving Pool**:
The subset of healthy WARP Instances eligible to serve proxy traffic. WarpNest keeps at most one WARP Instance per observed Exit IP in the Serving Pool.
_Avoid_: Active list, primary pool

**Target Serving Size**:
The desired number of distinct-Exit-IP WARP Instances in the Serving Pool.
_Avoid_: Registration count, account count

**Registration Budget**:
The configured maximum number of WARP Registrations that WarpNest may create or retain while trying to reach the Target Serving Size.
_Avoid_: Unlimited registration, target pool size

**Standby Pool**:
Healthy WARP Instances whose Exit IP duplicates an instance already present in the Serving Pool. Standby Pool instances are excluded from automatic pool scheduling but may serve traffic when explicitly selected.
_Avoid_: Failed pool, unused proxies

**Degraded Pool**:
A Proxy Pool state where WarpNest has fewer distinct-Exit-IP Serving Pool instances than the Target Serving Size, while at least one instance remains serviceable.
_Avoid_: Failed service, startup failure

**Pool Restoration**:
The restart behavior that prefers the previous Serving Pool and Standby Pool memberships before correcting them with fresh Health Check and Exit Probe results.
_Avoid_: Pool persistence, guaranteed sticky IP

## Example Dialogue

Developer: "Can we guarantee every WARP Instance has a different Exit IP?"

Domain expert: "No. WarpNest should probe each WARP Instance, observe its Exit IP, and prefer a Proxy Pool made of instances with distinct Exit IPs."

Developer: "What happens when two WARP Instances show the same Exit IP?"

Domain expert: "Only one should enter the Serving Pool. The other can stay healthy in the Standby Pool until it is needed."

Developer: "Can a client explicitly use a Standby Pool instance?"

Domain expert: "Yes. Automatic scheduling uses the Serving Pool, but an explicit Instance Selector may route through a healthy Standby Pool instance."

Developer: "Does WarpNest only import existing WARP settings?"

Domain expert: "No. WarpNest should support creating a WARP Registration and then establishing a WARP Connection, similar to the lifecycle exposed by `warp-cli registration new` and `warp-cli connect`."

Developer: "Which Cloudflare enrollment model does WarpNest support?"

Domain expert: "WarpNest supports fully automatic Public WARP Registration for Cloudflare's public WARP service, not Zero Trust team enrollment."

Developer: "Does the first version support WARP+ or organization-managed features?"

Domain expert: "No. The Public WARP Scope is ordinary public WARP only."

Developer: "Do we need to copy the internal implementation details of `warp-cli` exactly?"

Domain expert: "No. WarpNest needs behavior equivalent to the WARP Lifecycle, while keeping implementation details replaceable."

Developer: "How does a client choose a specific WARP Instance through the shared proxy?"

Domain expert: "The shared Proxy Endpoint should route through the Serving Pool by default, and clients may provide an Instance Selector as the proxy username to request a specific WARP Instance."

Developer: "Can users rename the ID used by `id:<instance-id>` selectors?"

Domain expert: "No. Instance Identity is system-generated and stable. Users can add labels or groups for readability."

Developer: "If a selector asks for an unavailable instance, should WarpNest silently use another one?"

Domain expert: "No. A failed Instance Selector should fail the proxy connection rather than falling back to automatic selection."

Developer: "Does a group mean a region or exit type?"

Domain expert: "No. An Instance Group is a user-defined routing collection and does not promise geography, performance, or a specific Exit IP type."

Developer: "Can `group:<name>` silently use duplicate-exit standby instances?"

Domain expert: "Only when Standby Fallback is explicitly enabled. By default, group selectors use Serving Pool instances only."

Developer: "Does proxy username identify an authenticated user?"

Domain expert: "No. The proxy username carries the Instance Selector; Proxy Authentication uses a shared secret in the password field."

Developer: "Does HTTP proxying need a custom selector header?"

Domain expert: "No. HTTP proxying uses the same username/password semantics as SOCKS5: username for Instance Selector and password for the shared secret."

Developer: "When does WarpNest choose an instance for proxied traffic?"

Domain expert: "It chooses once per proxy connection from healthy Serving Pool instances, preferring the one with the fewest active connections."

Developer: "Should WarpNest migrate live connections when an instance's Exit IP changes?"

Domain expert: "No. Connection Binding keeps live traffic on the selected WARP Instance; pool changes only affect new connections."

Developer: "Can the first version ignore UDP?"

Domain expert: "No. UDP Proxying is required so DNS and other UDP traffic can use the selected WARP Instance instead of leaking outside the proxy path."

Developer: "Does every proxy protocol need UDP support?"

Domain expert: "No. SOCKS5 should support UDP Association, while HTTP proxy support can remain focused on ordinary HTTP proxying and HTTP CONNECT."

Developer: "Can WarpNest use host DNS to resolve proxy targets before connecting through WARP?"

Domain expert: "No. The Proxy DNS Boundary requires target-name resolution to stay inside the selected WARP Instance path."

Developer: "Is an Exit Probe the same thing as a Health Check?"

Domain expert: "No. An Exit Probe discovers the current Exit IP, while a Health Check decides whether the WARP Instance can carry traffic."

Developer: "Should one external IP-check service be the sole source of truth?"

Domain expert: "No. Probe Consensus can use multiple endpoints and should avoid changing pool membership when observations disagree."

Developer: "Should failed operations retry immediately forever?"

Domain expert: "No. Retry Discipline requires per-operation backoff with jitter, global concurrency limits, and no automatic retry for clear authorization or policy failures."

Developer: "Can WarpNest keep clients on the same exit after restart?"

Domain expert: "It should try by restoring previous pool memberships and Last Observed Exit IPs, but fresh probes remain authoritative."

Developer: "Do users configure how many registrations to create or how many exits they want?"

Domain expert: "They configure the Target Serving Size and a Registration Budget. WarpNest tries to reach the target with distinct Exit IPs without exceeding the budget."

Developer: "Should WarpNest refuse to start if it cannot reach the Target Serving Size?"

Domain expert: "No. It should enter a Degraded Pool state, serve with the available distinct exits, and keep trying within the Registration Budget."

Developer: "Should WarpNest constantly register and delete devices to search for better exits?"

Domain expert: "No. The Registration Lifecycle should be conservative: restore first, create only within budget when needed, and prune only for explicit or long-term unhealthy cases."

Developer: "Does fully automatic Public WARP Registration mean unlimited registration?"

Domain expert: "No. It means WarpNest can register without manual import, but still within the configured Registration Budget and external service limits."

Developer: "How do users operate WarpNest?"

Domain expert: "Through the local Control Plane: CLI commands, a configuration file, and a local-only Management API."

Developer: "Where does WarpNest keep desired configuration versus remembered runtime state?"

Domain expert: "Desired behavior belongs in the Configuration File. Registrations, restoration data, last observations, and lifecycle state belong in the State Store."

Developer: "What should status output include?"

Domain expert: "Pool Status should show readiness, pool membership, Exit IP observations, active connections, probe timing, and recent errors, but never reveal sensitive WARP Registration material."

Developer: "Should logs include proxy targets and registration responses by default?"

Domain expert: "No. Private Observability means logs and status expose operational state while redacting secrets and avoiding traffic target logging by default."

Developer: "Should proxy and management listeners be public by default?"

Domain expert: "No. Local-First Exposure means they bind locally by default, and external exposure requires explicit configuration and authentication."

Developer: "Which operating system is the first-class target?"

Domain expert: "WarpNest is Linux-first, while keeping platform-specific concerns isolated for future macOS and Windows support."

Developer: "Does WarpNest need to be installed as a system service to work?"

Domain expert: "No. Daemon Mode is the core runtime. System service integration can wrap it later."

Developer: "Should WarpNest use the system VPN route for proxy traffic?"

Domain expert: "No. WarpNest should use a User-Space Data Plane so each proxy connection can be routed through the selected WARP Instance without changing host-wide routing."
