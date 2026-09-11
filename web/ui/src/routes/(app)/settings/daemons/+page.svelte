<script lang="ts">
	import { workspace } from '$lib/api/workspaces.svelte';
	import * as Card from '$lib/components/ui/card';
	import * as Item from '$lib/components/ui/item';
	import { Switch } from '$lib/components/ui/switch';
	import { Input } from '$lib/components/ui/input';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { Bot, ShieldCheck, Terminal } from '@lucide/svelte';
	import { useDebounce } from 'runed';
	import { create } from '@bufbuild/protobuf';
	import { WorkspaceSettingsSchema } from '$lib/gen/nokku/v1/workspace_pb';
	import { durationFromMs } from '@bufbuild/protobuf/wkt';
	import { DaemonConfigSchema } from '$lib/gen/nokku/v1/daemon_pb';

	const ws = $derived(workspace.get());

	// A proper protobuf message (not a plain object) so mutations and the
	// transport both work. defaultDaemonConfig is always present, which keeps
	// the bindings below free of undefined-guards.
	let settings = $derived.by(() => {
		const s = create(WorkspaceSettingsSchema, ws.data?.settings);
		if (!s.defaultDaemonConfig) s.defaultDaemonConfig = create(DaemonConfigSchema);
		return s;
	});
	const daemonConfig = $derived(settings.defaultDaemonConfig!);

	const update = workspace.update();
	const set = useDebounce(() => update.mutate({ settings: settings }), 500);
</script>

<PageHeader
	icon={Bot}
	title="Daemon Defaults"
	description="How new daemons join the workspace and which SSH server settings they inherit on enrollment. Existing daemons keep their own configuration."
/>

<!-- Enrollment Policy -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<ShieldCheck size={18} />
			Enrollment Policy
		</Card.Title>
	</Card.Header>
	<Card.Content>
		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Auto-approve new daemons</Item.Title>
				<Item.Description>
					{settings.enrollAutoApprove
						? 'Daemons are automatically approved when they enroll with a valid token.'
						: 'New daemons require manual approval before they can connect.'}
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={settings.enrollAutoApprove}
					onCheckedChange={(v) => {
						settings.enrollAutoApprove = v;
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>
	</Card.Content>
</Card.Root>

<!-- Default Daemon Configuration -->
<Card.Root>
	<Card.Header>
		<Card.Title class="flex items-center gap-2 text-base">
			<Terminal size={18} />
			Default Configuration
		</Card.Title>
		<Card.Description>SSH server settings applied to daemons when they enroll.</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col gap-4">
		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Session recording</Item.Title>
				<Item.Description>Record every SSH session for later playback.</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={daemonConfig.recordSessions}
					onCheckedChange={(v) => {
						daemonConfig.recordSessions = v;
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Port forwarding</Item.Title>
				<Item.Description>Allow -L, -D and -R port forwards from sessions.</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={daemonConfig.allowForwarding}
					onCheckedChange={(v) => {
						daemonConfig.allowForwarding = v;
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Agent forwarding</Item.Title>
				<Item.Description
					>Expose the client's ssh-agent to sessions via SSH_AUTH_SOCK.</Item.Description
				>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={daemonConfig.allowAgentForwarding}
					onCheckedChange={(v) => {
						daemonConfig.allowAgentForwarding = v;
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Gateway ports</Item.Title>
				<Item.Description>
					Allow remote (-R) forwards to bind addresses other than loopback.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={daemonConfig.gatewayPorts}
					onCheckedChange={(v) => {
						daemonConfig.gatewayPorts = v;
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Pre-auth banner</Item.Title>
				<Item.Description>
					Show clients a banner describing session policy before login.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={daemonConfig.banner}
					onCheckedChange={(v) => {
						daemonConfig.banner = v;
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Max sessions per connection</Item.Title>
				<Item.Description>Limit the number of sessions per connection.</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Input
					id="cfg-max-sessions"
					type="number"
					min="0"
					value={daemonConfig.maxSessions}
					oninput={(e) => {
						daemonConfig.maxSessions = Number((e.currentTarget as HTMLInputElement).value);
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Max concurrent connections</Item.Title>
				<Item.Description>Limit the number of concurrent connections.</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Input
					id="cfg-max-conns"
					type="number"
					min="0"
					value={daemonConfig.maxConnections}
					oninput={(e) => {
						daemonConfig.maxConnections = Number((e.currentTarget as HTMLInputElement).value);
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Max startup connections</Item.Title>
				<Item.Description>
					Limit connections still completing the pre-auth handshake. Zero disables the cap.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Input
					id="cfg-max-startups"
					type="number"
					min="0"
					value={daemonConfig.maxStartups}
					oninput={(e) => {
						daemonConfig.maxStartups = Number((e.currentTarget as HTMLInputElement).value);
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Max channels per connection</Item.Title>
				<Item.Description>
					Limit channels a single connection may hold open. Zero disables the cap.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Input
					id="cfg-max-channels"
					type="number"
					min="0"
					value={daemonConfig.maxChannels}
					oninput={(e) => {
						daemonConfig.maxChannels = Number((e.currentTarget as HTMLInputElement).value);
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Drop retired CA</Item.Title>
				<Item.Description>
					Stop trusting the previously rotated CA immediately after a rollover.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Switch
					checked={daemonConfig.dropRetiredCa}
					onCheckedChange={(v) => {
						daemonConfig.dropRetiredCa = v;
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Connection rate</Item.Title>
				<Item.Description>
					New connections per second per source IP. Zero disables rate limiting.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Input
					id="cfg-conn-rate"
					type="number"
					min="0"
					value={daemonConfig.connRate}
					oninput={(e) => {
						daemonConfig.connRate = Number((e.currentTarget as HTMLInputElement).value);
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Rate burst</Item.Title>
				<Item.Description>
					Short bursts of connections allowed above the steady rate.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Input
					id="cfg-conn-rate-burst"
					type="number"
					min="0"
					value={daemonConfig.connRateBurst}
					oninput={(e) => {
						daemonConfig.connRateBurst = Number((e.currentTarget as HTMLInputElement).value);
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>

		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>Client alive interval (seconds)</Item.Title>
				<Item.Description>
					How often the server probes idle clients. Zero disables keepalive probing.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				<Input
					id="cfg-alive-interval"
					type="number"
					min="0"
					value={daemonConfig.clientAliveInterval?.seconds}
					oninput={(e) => {
						let seconds = Number((e.currentTarget as HTMLInputElement).value);
						daemonConfig.clientAliveInterval = durationFromMs(
							Math.max(0, Math.floor(seconds)) * 1000
						);
						set();
					}}
				/>
			</Item.Actions>
		</Item.Root>
	</Card.Content>
</Card.Root>
