<script lang="ts">
	import { serviceAccount } from '$lib/api/service_account.svelte';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Command from '$lib/components/ui/command';
	import { Separator } from '$lib/components/ui/separator';
	import SearchPopover from '$lib/components/utils/SearchPopover.svelte';
	import UserAvatar from '$lib/components/utils/UserAvatar.svelte';
	import { Bot, Check, CirclePlus } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import { csv, setParams } from '$lib/components/audit/audit';

	let open = $state(false);
	let query = $state('');
	const debounced = new Debounced(() => query, 250);
	const opts = () => ({ query: debounced.current || undefined, limit: 20 });
	const members = workspace.listMembers(opts, () => open);
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
	loading={members.isLoading || serviceAccounts.isLoading}
>
	{#snippet trigger(props)}
		<Button {...props} variant="outline" size="sm" class="h-8 rounded-full border-dashed">
			<CirclePlus />
			Actor
			{#if selected.length}
				<Separator orientation="vertical" class="mx-1 h-4" />
				<Badge variant="secondary" class="rounded-sm px-1 font-normal">
					{selected.length} selected
				</Badge>
			{/if}
		</Button>
	{/snippet}

	{#if members.data?.members.length}
		<Command.Group heading="People">
			{#each members.data.members as m (m.id)}
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
