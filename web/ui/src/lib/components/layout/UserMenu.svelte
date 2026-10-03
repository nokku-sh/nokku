<script lang="ts">
	import type { Snippet } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth } from '#lib/api/auth.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { LogOut } from '@lucide/svelte';
	import { UserRoutes } from './routes';

	interface Props {
		trigger: Snippet<[Record<string, unknown>]>;
		side?: 'top' | 'right' | 'bottom' | 'left';
		align?: 'start' | 'center' | 'end';
	}

	let { trigger, side = 'bottom', align = 'end' }: Props = $props();

	const me = user.self();
	const logout = auth.logout();
	const pages = UserRoutes.flatMap((r) => r.items ?? [r]);
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		{#snippet child({ props })}
			{@render trigger(props)}
		{/snippet}
	</DropdownMenu.Trigger>
	<DropdownMenu.Content class="min-w-56" {side} {align} sideOffset={4}>
		<DropdownMenu.Label class="p-0 font-normal">
			<div class="flex items-center gap-2 px-1 py-1.5">
				<UserAvatar user={me.data} />
				<div class="grid flex-1 text-sm leading-tight">
					<span class="truncate font-semibold">{me.data?.name}</span>
					<span class="truncate text-xs text-muted-foreground">{me.data?.email}</span>
				</div>
			</div>
		</DropdownMenu.Label>
		<DropdownMenu.Separator />
		<DropdownMenu.Group>
			{#each pages as p (p.url)}
				<DropdownMenu.Item onSelect={() => goto(p.url)}>
					<p.icon />
					{p.title}
				</DropdownMenu.Item>
			{/each}
		</DropdownMenu.Group>
		<DropdownMenu.Separator />
		<DropdownMenu.Item onSelect={() => logout.mutate({})}>
			<LogOut />
			Log out
		</DropdownMenu.Item>
	</DropdownMenu.Content>
</DropdownMenu.Root>
