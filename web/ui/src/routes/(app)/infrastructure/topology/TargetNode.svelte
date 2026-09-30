<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';
	import { Server, Pencil, Network, Tag, Globe, Tags } from '@lucide/svelte';
	import { Handle, Position, type NodeProps } from '@xyflow/svelte';

	let { data }: NodeProps = $props();
	let target = $derived(data as Target);

	let principalCount = $derived(target.principals?.length || 0);
	let endpoints = $derived(target.endpoints || []);

	let tags = $derived(target.tags || target.metadata?.tags?.split(',') || []);
</script>

<div class="group relative">
	<Card.Root class="w-[360px] p-0">
		<Card.Content class="space-y-4 p-0">
			<div class="rounded-t-xl border-b border-border/50 bg-background p-4">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-3">
						<div
							class="flex h-10 w-10 items-center justify-center rounded-md border border-chart-1/20 bg-chart-1/10"
						>
							<Server class="text-chart-1" size={20} />
						</div>
						<div class="space-y-0.5">
							<h3 class="font-mono text-sm font-bold tracking-tight uppercase">
								{target.name}
							</h3>
						</div>
					</div>
					<Button
						variant="ghost"
						size="icon"
						href={`/infrastructure/targets?id=${target.id}`}
						aria-label={`Open ${target.name}`}
					>
						<Pencil />
					</Button>
				</div>
			</div>

			<div class="flex flex-col">
				{#if target.description}
					<div class="mb-4 px-4 text-sm text-muted-foreground">
						<p class="line-clamp-2 leading-relaxed">{target.description}</p>
					</div>
				{/if}

				<div class="grid grid-cols-2 divide-x divide-border/50 border-y border-border/50 px-2">
					<div class="p-2.5">
						<div class="mb-2 flex items-center gap-2 text-xs font-medium text-muted-foreground">
							<Network size={14} />
							<span>Endpoints</span>
						</div>
						<div class="space-y-1">
							{#each endpoints.slice(0, 2) as endpoint}
								<div
									class="flex items-center gap-1.5 overflow-hidden rounded-sm bg-background px-1.5 py-1"
								>
									<Globe class="text-primary" size={12} />
									<code class="w-full truncate text-2xs font-medium">{endpoint}</code>
								</div>
							{/each}
							{#if endpoints.length > 2}
								<div class="pl-1 text-2xs text-muted-foreground">
									+{endpoints.length - 2} more
								</div>
							{/if}
							{#if endpoints.length === 0}
								<span class="text-2xs text-muted-foreground italic">No endpoints</span>
							{/if}
						</div>
					</div>

					<div class="p-2.5">
						<div class="mb-2 flex items-center gap-2 text-xs font-medium text-muted-foreground">
							<Tags size={14} />
							<span>Tags</span>
						</div>
						<div class="space-y-1">
							{#each tags.slice(0, 2) as tag}
								<div
									class="flex items-center gap-1.5 overflow-hidden rounded-sm bg-background px-1.5 py-1"
								>
									<Tag class="text-primary" size={12} />
									<code class="w-full truncate text-2xs font-medium">{tag}</code>
								</div>
							{/each}
							{#if tags.length > 2}
								<div class="pl-1 text-2xs text-muted-foreground">
									+{tags.length - 2} more
								</div>
							{/if}
							{#if tags.length === 0}
								<span class="text-2xs text-muted-foreground italic">No tags</span>
							{/if}
						</div>
					</div>
				</div>

				<div class="flex items-center justify-between bg-muted/10 p-2.5 px-4 text-xs">
					<span class="text-muted-foreground">Total principals</span>
					<Badge variant={principalCount > 0 ? 'default' : 'secondary'} class="h-5">
						{principalCount}
					</Badge>
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<Handle
		type="source"
		position={Position.Bottom}
		class="h-3! w-3! border-4! border-background! bg-chart-1! transition-all hover:h-4! hover:w-4!"
	/>
</div>
