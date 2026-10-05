<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as HoverCard from '#lib/components/ui/hover-card/index.js';
	import { team } from '#lib/api/team.svelte.js';
	import { Users } from '@lucide/svelte';

	type Props = {
		userId: string;
	};
	let { userId }: Props = $props();

	const teamsQuery = team.listForUser(() => userId);
	const teams = $derived(teamsQuery.data ?? []);

	const teamCount = $derived(teams.length);
	const hasTeams = $derived(teamCount > 0);
</script>

{#if hasTeams}
	<HoverCard.Root openDelay={200}>
		<HoverCard.Trigger>
			<Badge variant="secondary" class="cursor-pointer gap-1.5 text-xs font-medium">
				<Users class="h-3 w-3" />
				{teamCount}
				{teamCount === 1 ? 'Team' : 'Teams'}
			</Badge>
		</HoverCard.Trigger>
		<HoverCard.Content class="max-h-96 w-80 overflow-y-auto p-3">
			<div class="space-y-2">
				{#each teams as team (team.id)}
					<div
						class="flex items-center gap-3 rounded-lg border bg-card p-3 text-card-foreground transition-colors hover:bg-accent"
					>
						<div
							class="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md bg-muted/50"
						>
							<Users class="size-4 text-muted-foreground" />
						</div>

						<div class="flex-1 space-y-1 overflow-hidden">
							<div class="flex items-center gap-2">
								<p class="truncate text-sm font-medium">{team.name}</p>
								{#if team.memberCount && team.memberCount > 0}
									<Badge variant="outline" class="text-2xs leading-none">
										{team.memberCount}
										{team.memberCount === 1 ? 'member' : 'members'}
									</Badge>
								{/if}
							</div>
							{#if team.description}
								<p class="line-clamp-2 text-xs text-muted-foreground">
									{team.description}
								</p>
							{/if}
						</div>
					</div>
				{/each}
			</div>
		</HoverCard.Content>
	</HoverCard.Root>
{:else}
	<Badge variant="outline" class="gap-1.5 text-xs">
		<Users class="h-3 w-3" />
		No Teams
	</Badge>
{/if}
