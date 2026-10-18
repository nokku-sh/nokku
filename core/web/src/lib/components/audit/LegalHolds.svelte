<script lang="ts">
	import { legalHolds } from '#lib/api/legal-holds.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import * as Sheet from '#lib/components/ui/sheet/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { confirm } from '#lib/hooks/index.js';
	import PlanBadge from '#lib/components/blocks/PlanBadge.svelte';
	import { formatTs } from '#lib/utils.js';
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { Archive, Lock } from '@lucide/svelte';

	let open = $state(false);

	const can = user.can();
	const has = useFeatures();
	const available = $derived(has('legal_hold'));
	const holds = legalHolds.list();
	const create = legalHolds.create();
	const release = legalHolds.release();

	let reason = $state('');
	let from = $state('');
	let until = $state('');
	const valid = $derived(
		reason.trim().length >= 3 && !!from && (!until || new Date(until) > new Date(from))
	);

	async function place(e: SubmitEvent) {
		e.preventDefault();
		if (!valid) return;
		await create.mutateAsync({
			reason: reason.trim(),
			startsAt: timestampFromDate(new Date(from)),
			endsAt: until ? timestampFromDate(new Date(until)) : undefined
		});
		reason = from = until = '';
	}

	function askRelease(id: string, why: string) {
		void confirm({
			title: 'Release this legal hold?',
			description: `"${why}". Retention deletes what it kept on its next run, if the plan's retention has passed.`,
			confirmText: 'Release',
			onConfirm: () => release.mutateAsync({ id })
		});
	}
</script>

<Sheet.Root bind:open>
	<Sheet.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline">
				<Lock data-icon="inline-start" />
				Legal holds
				{#if holds.data?.length}<Badge variant="muted">{holds.data.length}</Badge>{/if}
			</Button>
		{/snippet}
	</Sheet.Trigger>
	<Sheet.Content class="flex w-full flex-col gap-0 sm:max-w-md">
		<Sheet.Header>
			<Sheet.Title class="flex items-center gap-2">
				Legal holds
				<PlanBadge feature="legal_hold" />
			</Sheet.Title>
			<Sheet.Description>
				Audit events and recordings from a held time range are kept past their retention, until the
				hold is released. Deleting the workspace still deletes them.
			</Sheet.Description>
		</Sheet.Header>

		<div class="flex flex-1 flex-col gap-6 overflow-y-auto px-4 pb-4">
			{#if can.admin && available}
				<form class="rounded-xl border p-4" onsubmit={place}>
					<Field.Group>
						<Field.Field>
							<Field.Label for="hold-reason">Reason</Field.Label>
							<Input
								id="hold-reason"
								bind:value={reason}
								placeholder="Incident 2026-10 on db-1"
								maxlength={1000}
							/>
						</Field.Field>
						<div class="grid gap-4 sm:grid-cols-2">
							<Field.Field>
								<Field.Label for="hold-from">From</Field.Label>
								<Input id="hold-from" type="datetime-local" bind:value={from} />
							</Field.Field>
							<Field.Field>
								<Field.Label for="hold-until">Until</Field.Label>
								<Input id="hold-until" type="datetime-local" bind:value={until} />
								<Field.Description>Empty holds until released.</Field.Description>
							</Field.Field>
						</div>
						<Button type="submit" disabled={!valid || create.isPending}>
							{#if create.isPending}<Spinner data-icon="inline-start" />{/if}
							Place hold
						</Button>
					</Field.Group>
				</form>
			{/if}

			{#if holds.data?.length}
				<Item.Group class="gap-2">
					{#each holds.data as hold (hold.id)}
						<Item.Root variant="outline">
							<Item.Content>
								<Item.Title>{hold.reason}</Item.Title>
								<Item.Description>
									{formatTs(hold.startsAt, 'withTime')} until {hold.endsAt
										? formatTs(hold.endsAt, 'withTime')
										: 'released'}
								</Item.Description>
							</Item.Content>
							{#if can.admin}
								<Item.Actions>
									<Button
										variant="ghost"
										size="sm"
										onclick={() => askRelease(hold.id, hold.reason)}
									>
										Release
									</Button>
								</Item.Actions>
							{/if}
						</Item.Root>
					{/each}
				</Item.Group>
			{:else if !holds.isLoading}
				<Empty.Root class="border border-dashed">
					<Empty.Header>
						<Empty.Media variant="icon"><Archive /></Empty.Media>
						<Empty.Title>Nothing is held</Empty.Title>
						<Empty.Description>Retention runs as the plan says.</Empty.Description>
					</Empty.Header>
				</Empty.Root>
			{/if}
		</div>
	</Sheet.Content>
</Sheet.Root>
