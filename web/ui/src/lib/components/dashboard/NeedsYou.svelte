<script lang="ts">
	import { daemon as daemonApi } from '#lib/api/daemons.svelte.js';
	import StatusDot from '#lib/components/blocks/StatusDot.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Item from '#lib/components/ui/item/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { DaemonStatus } from '#lib/gen/nokku/v1/daemon_pb.js';
	import { Check, ChevronRight, CircleCheck } from '@lucide/svelte';
	import type { Issue } from './issues';

	interface Props {
		issues: Issue[];
		loading: boolean;
		canEdit: boolean;
	}

	let { issues, loading, canEdit }: Props = $props();

	const update = daemonApi.update();
</script>

<Card.Root class="gap-3">
	<Card.Header>
		<Card.Title>Needs you</Card.Title>
		<Card.Description>Only what someone has to act on.</Card.Description>
	</Card.Header>
	<Card.Content>
		{#if loading}
			<div class="flex flex-col gap-2">
				<Skeleton class="h-14 w-full" />
				<Skeleton class="h-14 w-full" />
			</div>
		{:else if !issues.length}
			<Empty.Root class="gap-3 p-4">
				<Empty.Header>
					<Empty.Media variant="icon" class="bg-success/15 text-success"
						><CircleCheck /></Empty.Media
					>
					<Empty.Title>Nothing needs you</Empty.Title>
					<Empty.Description>Daemons are up, CAs are fresh, no failure spikes.</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<Item.Group class="gap-2">
				{#each issues as issue (issue.id)}
					<Item.Root variant="outline" size="sm" class="items-start">
						<Item.Media class="pt-1.5"><StatusDot tone={issue.tone} live /></Item.Media>
						<Item.Content>
							<Item.Title>{issue.title}</Item.Title>
							<Item.Description>{issue.detail}</Item.Description>
							{#if issue.approve && canEdit}
								<div class="mt-2 flex flex-wrap gap-1.5">
									{#each issue.approve as d (d.id)}
										<Button
											size="xs"
											variant="outline"
											disabled={update.isPending}
											onclick={() => update.mutate({ id: d.id, status: DaemonStatus.ACCEPTED })}
										>
											{#if update.isPending && update.variables?.id === d.id}
												<Spinner data-icon="inline-start" />
											{:else}
												<Check data-icon="inline-start" />
											{/if}
											<span class="font-mono">{d.name}</span>
										</Button>
									{/each}
								</div>
							{/if}
						</Item.Content>
						<Item.Actions>
							<Button
								size="icon-sm"
								variant="ghost"
								href={issue.href}
								aria-label={`Open: ${issue.title}`}
							>
								<ChevronRight />
							</Button>
						</Item.Actions>
					</Item.Root>
				{/each}
			</Item.Group>
		{/if}
	</Card.Content>
</Card.Root>
