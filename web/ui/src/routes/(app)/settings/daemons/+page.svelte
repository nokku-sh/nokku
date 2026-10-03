<script lang="ts">
	import { workspace } from '#lib/api/workspaces.svelte.js';
	import SaveStatus from '#lib/components/blocks/SaveStatus.svelte';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import { DaemonConfigSchema, type DaemonConfig } from '#lib/gen/nokku/v1/daemon_pb.js';
	import { WorkspaceSettingsSchema } from '#lib/gen/nokku/v1/workspace_pb.js';
	import { useAutoSave } from '#lib/hooks/index.js';
	import { atLeast } from '#lib/roles.js';
	import { create } from '@bufbuild/protobuf';

	const ws = workspace.get();
	const update = workspace.update();
	const canEdit = $derived(atLeast(ws.data?.role, 'admin'));

	// A real protobuf message, not a plain object, so the transport accepts it.
	const settings = $derived.by(() => {
		const s = create(WorkspaceSettingsSchema, ws.data?.settings);
		if (!s.defaultDaemonConfig) s.defaultDaemonConfig = create(DaemonConfigSchema);
		return s;
	});
	const config = $derived(settings.defaultDaemonConfig!);

	const autoSave = useAutoSave(() => update.mutateAsync({ settings }));

	type Toggle = {
		key: keyof Pick<
			DaemonConfig,
			| 'recordSessions'
			| 'allowForwarding'
			| 'allowAgentForwarding'
			| 'gatewayPorts'
			| 'dropRetiredCa'
		>;
		title: string;
		description: string;
	};

	const toggles: Toggle[] = [
		{
			key: 'recordSessions',
			title: 'Session recording',
			description: 'Record every SSH session for later playback.'
		},
		{
			key: 'allowForwarding',
			title: 'Port forwarding',
			description: 'Allow -L, -D and -R port forwards from sessions.'
		},
		{
			key: 'allowAgentForwarding',
			title: 'Agent forwarding',
			description: "Expose the client's ssh-agent to sessions through SSH_AUTH_SOCK."
		},
		{
			key: 'gatewayPorts',
			title: 'Gateway ports',
			description: 'Let remote (-R) forwards bind to addresses other than loopback.'
		},
		{
			key: 'dropRetiredCa',
			title: 'Drop retired CA',
			description: 'Stop trusting the previous CA right after a rollover.'
		}
	];
</script>

<PageHeader
	title="Daemon defaults"
	description="SSH server settings new daemons inherit when they enroll, existing daemons keep their own"
/>

<Card.Root>
	<Card.Header>
		<Card.Title>New daemons start with</Card.Title>
		<Card.Description
			>Auto-approval is not here, it is set on each enrollment token.</Card.Description
		>
	</Card.Header>
	<Card.Content>
		<Item.Group class="gap-3">
			{#each toggles as t (t.key)}
				<Item.Root variant="outline">
					<Item.Content>
						<Item.Title>{t.title}</Item.Title>
						<Item.Description>{t.description}</Item.Description>
					</Item.Content>
					<Item.Actions>
						{#if ws.isLoading}
							<Skeleton class="h-5 w-9 rounded-full" />
						{:else}
							<Switch
								aria-label={t.title}
								checked={config[t.key]}
								disabled={!canEdit}
								onCheckedChange={(v) => {
									config[t.key] = v;
									autoSave.save();
								}}
							/>
						{/if}
					</Item.Actions>
				</Item.Root>
			{/each}
		</Item.Group>
	</Card.Content>
	<Card.Footer>
		<SaveStatus
			state={autoSave.saveState}
			idleText={canEdit ? 'Changes save automatically' : 'Only admins can change this'}
		/>
	</Card.Footer>
</Card.Root>
