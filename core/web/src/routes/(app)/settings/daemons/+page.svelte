<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { user } from '#lib/api/user.svelte.js';
	import { useFeatures, workspace } from '#lib/api/workspaces.svelte.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import PlanBadge from '#lib/components/blocks/PlanBadge.svelte';
	import { durationFromMs, durationMs } from '@bufbuild/protobuf/wkt';
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
	const me = user.self();
	const update = workspace.update();
	const canEdit = $derived(atLeast(me.data?.role, WorkspaceRole.OWNER));

	// A real protobuf message, not a plain object, so the transport accepts it.
	const settings = $derived.by(() => {
		const s = create(WorkspaceSettingsSchema, ws.data?.settings);
		if (!s.defaultDaemonConfig) s.defaultDaemonConfig = create(DaemonConfigSchema);
		return s;
	});
	const config = $derived(settings.defaultDaemonConfig!);

	// Only the daemon defaults are sent, so a setting the plan no longer allows never blocks the save.
	const autoSave = useAutoSave(() =>
		update.mutateAsync({
			settings: create(WorkspaceSettingsSchema, { defaultDaemonConfig: config })
		})
	);

	const has = useFeatures();
	const idleMinutes = $derived(
		Math.round(durationMs(ws.data?.settings?.sessionIdleTimeout ?? durationFromMs(0)) / 60_000)
	);
	// A downgraded workspace may still turn it off.
	const idleLocked = $derived(has('idle_timeout') === false && idleMinutes === 0);
	const idleChoices = [
		{ minutes: 0, label: 'Never' },
		{ minutes: 5, label: 'After 5 minutes' },
		{ minutes: 15, label: 'After 15 minutes' },
		{ minutes: 30, label: 'After 30 minutes' },
		{ minutes: 60, label: 'After 1 hour' },
		{ minutes: 240, label: 'After 4 hours' }
	];
	const idleLabel = $derived(
		idleChoices.find((c) => c.minutes === idleMinutes)?.label ?? `After ${idleMinutes} minutes`
	);

	function setIdle(minutes: number) {
		update.mutate({
			settings: create(WorkspaceSettingsSchema, {
				sessionIdleTimeout: durationFromMs(minutes * 60_000)
			})
		});
	}

	type Toggle = {
		key: keyof Pick<
			DaemonConfig,
			'recordSessions' | 'allowForwarding' | 'allowAgentForwarding' | 'gatewayPorts'
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
			idleText={canEdit ? 'Changes save automatically' : 'Only the owner can change this'}
		/>
	</Card.Footer>
</Card.Root>

<Card.Root class="mt-4">
	<Card.Header>
		<Card.Title>Every daemon</Card.Title>
		<Card.Description>Applies to all daemons at once, enrolled or not.</Card.Description>
	</Card.Header>
	<Card.Content>
		<Item.Root variant="outline">
			<Item.Content>
				<Item.Title>
					Close idle terminals
					<PlanBadge feature="idle_timeout" />
				</Item.Title>
				<Item.Description>
					Ends a terminal session after this long without a keystroke. Commands without a terminal,
					file copies and port forwards keep running. Servers set up with nk sync are not covered.
				</Item.Description>
			</Item.Content>
			<Item.Actions>
				{#if ws.isLoading}
					<Skeleton class="h-8 w-40" />
				{:else}
					<Select.Root
						type="single"
						value={String(idleMinutes)}
						onValueChange={(v) => setIdle(Number(v))}
						disabled={!canEdit || idleLocked || update.isPending}
					>
						<Select.Trigger class="w-44" aria-label="Close idle terminals">
							{idleLabel}
						</Select.Trigger>
						<Select.Content>
							{#each idleChoices as c (c.minutes)}
								<Select.Item value={String(c.minutes)}>{c.label}</Select.Item>
							{/each}
						</Select.Content>
					</Select.Root>
				{/if}
			</Item.Actions>
		</Item.Root>
	</Card.Content>
</Card.Root>
