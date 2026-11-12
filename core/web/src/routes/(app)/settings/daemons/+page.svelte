<script lang="ts">
	import { plural } from '#lib/api/bulk.js';
	import { daemon } from '#lib/api/daemons.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { useFeatures, workspace } from '#lib/api/workspaces.svelte.js';
	import DaemonRules from '#lib/components/blocks/DaemonRules.svelte';
	import PlanBadge from '#lib/components/blocks/PlanBadge.svelte';
	import SaveStatus from '#lib/components/blocks/SaveStatus.svelte';
	import SettingRow from '#lib/components/blocks/SettingRow.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { differing, ruleValue } from '#lib/daemon-rules.js';
	import { useAutoSave } from '#lib/hooks/index.js';
	import { durationFromMs, durationMs } from '@bufbuild/protobuf/wkt';

	const ws = workspace.get();
	const can = user.can();
	const update = workspace.updateDaemonDefaults();
	const saving = useAutoSave();

	// Unset defaults read as all off, like the daemon reads them.
	const defaults = $derived(ws.data && (ws.data.settings?.defaultDaemonConfig ?? {}));

	// The list is one page. Past that the count would be a guess, so it is left out.
	const daemons = daemon.list();
	const enrolled = $derived.by(() => {
		const list = daemons.data?.daemons ?? [];
		if (!defaults || !list.length || list.length < (daemons.data?.total ?? 0)) return undefined;
		const differ = list.filter((d) => differing(d.config, defaults) > 0).length;
		return `${list.length === 1 ? 'Your enrolled daemon keeps its' : `Your ${list.length} enrolled daemons keep their`} own rules. ${
			differ ? `${plural(differ, 'differs', 'differ')} from these.` : 'None differ from these.'
		}`;
	});

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

	// The global mutation handler toasts a failure, the footer offers the retry.
	const setIdle = (minutes: number) =>
		saving
			.track(() => update.mutateAsync({ sessionIdleTimeout: durationFromMs(minutes * 60_000) }))
			.catch(() => {});
</script>

<PageHeader
	title="Daemon defaults"
	description="The SSH rules a server starts with, and the ones every server shares"
>
	<SaveStatus
		state={saving.saveState}
		idleText={can.admin ? 'Changes save automatically' : 'Only admins can change this'}
		onRetry={saving.retry}
	/>
</PageHeader>

<Card.Root>
	<Card.Header>
		<Card.Title class="flex flex-wrap items-center gap-2">
			<h2>New daemons start with</h2>
			<Badge variant="info">Applies to new daemons only</Badge>
		</Card.Title>
		<Card.Description>
			{enrolled ?? 'Daemons that already enrolled keep their own rules.'} Change one on its server, under
			Settings.
		</Card.Description>
	</Card.Header>
	<Card.Content class="flex flex-col gap-3">
		<!-- Only the flipped rule goes out, so one the plan no longer allows never blocks the others. -->
		<DaemonRules
			values={defaults}
			disabled={!can.admin}
			onChange={(rule, value) =>
				saving.track(() => update.mutateAsync({ defaultDaemonConfig: ruleValue(rule.key, value) }))}
		/>
		<p class="text-xs text-muted-foreground">
			Auto-approval is not a default. It is set on each enrollment token.
		</p>
	</Card.Content>
</Card.Root>

<Card.Root>
	<Card.Header>
		<Card.Title class="flex flex-wrap items-center gap-2">
			<h2>Every daemon</h2>
			<Badge variant="warning">Applies to every daemon at once</Badge>
		</Card.Title>
		<Card.Description
			>One value for the whole workspace. A server cannot override it.</Card.Description
		>
	</Card.Header>
	<Card.Content>
		<SettingRow
			outline
			wide
			title="Close idle terminals"
			description="Ends a terminal session after this long without a keystroke. Commands without a terminal, file copies and port forwards keep running. Servers set up with nk sync are not covered."
			for="idle-timeout"
		>
			{#snippet badge()}<PlanBadge feature="idle_timeout" />{/snippet}
			{#if ws.data}
				<Select.Root
					type="single"
					value={String(idleMinutes)}
					onValueChange={(v) => setIdle(Number(v))}
					disabled={!can.admin || idleLocked || update.isPending}
				>
					<Select.Trigger id="idle-timeout" class="w-full sm:w-44">
						{idleLabel}
					</Select.Trigger>
					<Select.Content>
						<Select.Group>
							{#each idleChoices as c (c.minutes)}
								<Select.Item value={String(c.minutes)}>{c.label}</Select.Item>
							{/each}
						</Select.Group>
					</Select.Content>
				</Select.Root>
			{:else}
				<Skeleton class="h-8 w-44" />
			{/if}
		</SettingRow>
	</Card.Content>
</Card.Root>
