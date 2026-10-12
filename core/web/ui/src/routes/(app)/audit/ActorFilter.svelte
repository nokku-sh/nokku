<script lang="ts">
	import { serviceAccount } from '#lib/api/service_account.svelte.js';
	import { users } from '#lib/api/workspaces.svelte.js';
	import * as Command from '#lib/components/ui/command/index.js';
	import FilterButton from '#lib/components/blocks/FilterButton.svelte';
	import SearchPopover from '#lib/components/blocks/SearchPopover.svelte';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import { Bot, Check } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import { csv, setParams } from '#lib/components/audit/audit.js';

	let open = $state(false);
	let query = $state('');
	const debounced = new Debounced(() => query, 250);
	const opts = () => ({ query: debounced.current || undefined, limit: 20 });
	const people = users.list(opts, () => open);
	const serviceAccounts = serviceAccount.list(opts, () => open);

	const selected = $derived(csv('actor'));

	function toggle(id: string) {
		const next = selected.includes(id) ? selected.filter((s) => s !== id) : [...selected, id];
		setParams({ actor: next.join(',') || undefined });
	}
</script>

<SearchPopover
	bind:open
	bind:query
	placeholder="Search people, service accounts..."
	empty="Nobody matches."
	loading={people.isLoading || serviceAccounts.isLoading}
>
	{#snippet trigger(props)}
		<FilterButton
			{...props}
			title="Actor"
			selected={selected.length ? [`${selected.length}`] : []}
		/>
	{/snippet}

	{#if people.data?.users.length}
		<Command.Group heading="People">
			{#each people.data.users as m (m.id)}
				<Command.Item value={m.id} onSelect={() => toggle(m.id)}>
					<UserAvatar user={m} class="size-6" />
					<div class="flex min-w-0 flex-1 flex-col">
						<span class="truncate">{m.name}</span>
						<span class="truncate text-xs text-muted-foreground">{m.email}</span>
					</div>
					<Check class={selected.includes(m.id) ? 'text-primary' : 'invisible'} />
				</Command.Item>
			{/each}
		</Command.Group>
	{/if}
	{#if serviceAccounts.data?.serviceAccounts.length}
		<Command.Group heading="Service accounts">
			{#each serviceAccounts.data.serviceAccounts as sa (sa.id)}
				<Command.Item value={sa.id} onSelect={() => toggle(sa.id)}>
					<Bot />
					<span class="flex-1 truncate">{sa.name}</span>
					<Check class={selected.includes(sa.id) ? 'text-primary' : 'invisible'} />
				</Command.Item>
			{/each}
		</Command.Group>
	{/if}
	{#if selected.length}
		<Command.Separator />
		<Command.Group>
			<Command.Item class="justify-center" onSelect={() => setParams({ actor: undefined })}>
				Clear actors
			</Command.Item>
		</Command.Group>
	{/if}
</SearchPopover>
