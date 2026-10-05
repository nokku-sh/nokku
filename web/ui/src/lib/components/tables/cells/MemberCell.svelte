<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as HoverCard from '#lib/components/ui/hover-card/index.js';
	import { team } from '#lib/api/team.svelte.js';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import { Users } from '@lucide/svelte';

	type Props = {
		teamId: string;
		memberCount?: number;
	};
	let { teamId, memberCount = 0 }: Props = $props();

	// Members load when the hover card opens, so a page of teams costs no queries.
	let open = $state(false);
	const membersQuery = team.members(
		() => teamId,
		() => ({ enabled: open })
	);

	const hasMembers = $derived(memberCount > 0);
</script>

{#if hasMembers}
	<HoverCard.Root bind:open openDelay={200}>
		<HoverCard.Trigger>
			<Badge variant="secondary" class="cursor-pointer gap-1.5 text-xs font-medium">
				<Users class="size-3" />
				{memberCount}
				{memberCount === 1 ? 'Member' : 'Members'}
			</Badge>
		</HoverCard.Trigger>
		<HoverCard.Content class="max-h-96 w-80 overflow-y-auto p-3">
			<div class="space-y-2">
				{#if membersQuery.isPending}
					<p class="p-3 text-center text-xs text-muted-foreground">Loading members…</p>
				{:else}
					{#each membersQuery.data ?? [] as user (user.id)}
						<div
							class="flex items-center gap-3 rounded-lg border bg-card p-3 text-card-foreground transition-colors hover:bg-accent"
						>
							<UserAvatar {user} />

							<div class="flex-1 space-y-1 overflow-hidden">
								<div class="flex items-center gap-2">
									<p class="truncate text-sm font-medium">{user.name}</p>
									{#if user.emailVerified}
										<Badge variant="secondary" class="text-2xs leading-none">verified</Badge>
									{/if}
								</div>
								<div class="flex flex-col gap-0.5 text-xs text-muted-foreground">
									<span class="truncate">{user.email}</span>
								</div>
							</div>
						</div>
					{/each}
				{/if}
			</div>
		</HoverCard.Content>
	</HoverCard.Root>
{:else}
	<Badge variant="outline" class="gap-1.5 text-xs">
		<Users class="size-3" />
		No Members
	</Badge>
{/if}
