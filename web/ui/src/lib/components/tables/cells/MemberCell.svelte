<script lang="ts">
	import { Badge } from '$lib/components/ui/badge';
	import * as HoverCard from '$lib/components/ui/hover-card/index.js';
	import UserAvatar from '$lib/components/utils/UserAvatar.svelte';
	import { type WorkspaceMember } from '$lib/gen/nokku/v1/workspace_pb';
	import { Users } from '@lucide/svelte';

	type Props = {
		members: WorkspaceMember[];
	};
	let { members }: Props = $props();

	const memberCount = $derived(members.length);
	const hasMembers = $derived(memberCount > 0);
</script>

{#if hasMembers}
	<HoverCard.Root openDelay={200}>
		<HoverCard.Trigger>
			<Badge variant="secondary" class="cursor-pointer gap-1.5 text-xs font-medium">
				<Users class="h-3 w-3" />
				{memberCount}
				{memberCount === 1 ? 'Member' : 'Members'}
			</Badge>
		</HoverCard.Trigger>
		<HoverCard.Content class="max-h-96 w-80 overflow-y-auto p-3">
			<div class="space-y-2">
				<div class="space-y-2">
					{#each members as user (user.id)}
						<div
							class="flex items-center gap-3 rounded-lg border bg-card p-3 text-card-foreground transition-colors hover:bg-accent"
						>
							<UserAvatar {user} />

							<!-- User Info -->
							<div class="flex-1 space-y-1 overflow-hidden">
								<div class="flex items-center gap-2">
									<p class="truncate text-sm leading-none font-medium">{user.name}</p>
									<Badge variant="secondary" class="text-[10px] leading-none">
										{user.username}
									</Badge>
								</div>
								<div class="flex flex-col gap-0.5 text-xs text-muted-foreground">
									<span class="truncate">{user.email}</span>
								</div>
							</div>
						</div>
					{/each}
				</div>
			</div>
		</HoverCard.Content>
	</HoverCard.Root>
{:else}
	<Badge variant="outline" class="gap-1.5 text-xs">
		<Users class="h-3 w-3" />
		No Members
	</Badge>
{/if}
