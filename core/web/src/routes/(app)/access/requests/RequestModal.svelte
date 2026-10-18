<script lang="ts">
	import { accessRequests } from '#lib/api/access-requests.svelte.js';
	import FormModal from '#lib/components/blocks/FormModal.svelte';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { formatHours } from '#lib/utils.js';
	import { durationFromMs } from '@bufbuild/protobuf/wkt';
	import { Hand } from '@lucide/svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const targets = accessRequests.requestable(() => open);
	const create = accessRequests.create();

	const lengths = [1, 4, 8, 24, 24 * 7];

	let targetId = $state('');
	let username = $state('');
	let hours = $state(1);
	let reason = $state('');

	const target = $derived((targets.data ?? []).find((t) => t.id === targetId));

	async function onSubmit() {
		await create.mutateAsync({
			target: targetId,
			username,
			duration: durationFromMs(hours * 3_600_000),
			reason: reason.trim()
		});
		targetId = username = reason = '';
		hours = 1;
	}
</script>

<FormModal
	bind:open
	title="Request access"
	description="An admin approves it. The account then works for as long as you asked, and ends by itself."
	icon={Hand}
	submitLabel="Send request"
	submitDisabled={!target || !username || reason.trim().length < 3}
	{onSubmit}
>
	<Field.Field>
		<Field.Label for="request-target">Server</Field.Label>
		<Select.Root
			type="single"
			value={targetId}
			onValueChange={(v) => {
				targetId = v;
				username = '';
			}}
		>
			<Select.Trigger id="request-target" class="w-full">
				{target?.name ?? 'Pick a server'}
			</Select.Trigger>
			<Select.Content>
				{#each targets.data ?? [] as t (t.id)}
					<Select.Item value={t.id}>{t.name}</Select.Item>
				{:else}
					<p class="p-2 text-sm text-muted-foreground">No server is open for requests.</p>
				{/each}
			</Select.Content>
		</Select.Root>
	</Field.Field>
	<div class="grid gap-4 sm:grid-cols-2">
		<Field.Field>
			<Field.Label for="request-account">Account</Field.Label>
			<Select.Root type="single" bind:value={username} disabled={!target}>
				<Select.Trigger id="request-account" class="w-full font-mono">
					{username || 'Pick an account'}
				</Select.Trigger>
				<Select.Content>
					{#each target?.usernames ?? [] as u (u)}
						<Select.Item value={u} class="font-mono">{u}</Select.Item>
					{/each}
				</Select.Content>
			</Select.Root>
		</Field.Field>
		<Field.Field>
			<Field.Label for="request-length">For</Field.Label>
			<Select.Root type="single" value={String(hours)} onValueChange={(v) => (hours = Number(v))}>
				<Select.Trigger id="request-length" class="w-full">{formatHours(hours)}</Select.Trigger>
				<Select.Content>
					{#each lengths as h (h)}
						<Select.Item value={String(h)}>{formatHours(h)}</Select.Item>
					{/each}
				</Select.Content>
			</Select.Root>
		</Field.Field>
	</div>
	<Field.Field>
		<Field.Label for="request-reason">Reason</Field.Label>
		<Textarea
			id="request-reason"
			bind:value={reason}
			placeholder="Ticket OPS-123, the replica is lagging"
			maxlength={1000}
		/>
		<Field.Description>Goes to the admins and into the audit log.</Field.Description>
	</Field.Field>
</FormModal>
