<script lang="ts">
	import { workspace } from '$lib/api/workspaces.svelte';
	import * as Card from '$lib/components/ui/card';
	import * as Item from '$lib/components/ui/item';
	import { Switch } from '$lib/components/ui/switch';
	import PageHeader from '$lib/components/utils/PageHeader.svelte';
	import { Bot, Terminal } from '@lucide/svelte';
	import { useDebounce } from 'runed';
	import { create } from '@bufbuild/protobuf';
	import { WorkspaceSettingsSchema } from '$lib/gen/nokku/v1/workspace_pb';
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
	description="The SSH server settings new daemons inherit on enrollment. Existing daemons keep their own configuration. Auto-approval is set per enroll token."
/>

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
	</Card.Content>
</Card.Root>
