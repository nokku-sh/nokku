<script lang="ts">
	import { CircleCheck, CircleX, History } from '@lucide/svelte';
	import { util, workspace } from '$lib/api/workspaces.svelte';
	import ActivityModal from '$lib/components/modals/ActivityModal.svelte';
	import * as Empty from '$lib/components/ui/empty';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { createModalState } from '$lib/hooks';
	import type { EventLog } from '$lib/gen/nokku/v1/util_pb';
	import { auditStatusOk, formatTs } from '$lib/utils';

	interface Props {
		limit?: number;
		title?: string;
	}

	let { limit = 8, title = 'Recent activity' }: Props = $props();

	const modal = createModalState<EventLog>({} as EventLog);
	const logs = $derived(util.getLogs({ limit, offset: 0 }));
	const members = $derived(workspace.listMembers(() => ({ limit: 200 })));

	function actionLabel(action: string): string {
		const seg = action.split('/').filter(Boolean).pop() ?? action;
		return seg.replace(/([a-z])([A-Z])/g, '$1 $2');
	}

	function actorLabel(log: EventLog): string {
		if (log.actorEmail) return log.actorEmail;
		if (log.actorType === 'user') {
			const member = members.data?.members.find((m) => m.id === log.actorId);
			if (member) return member.name;
		}
		return log.actorType;
	}
</script>

<ActivityModal log={modal.selected} bind:open={modal.open} />

<div class="overflow-hidden rounded-xl border bg-card">
	<div class="flex items-center justify-between border-b px-4 py-3">
		<h3 class="text-sm font-semibold">{title}</h3>
		<a
			href="/activity"
			class="text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
		>
			View all
		</a>
	</div>

	{#if logs.isPending}
		<div class="space-y-1 p-2">
			{#each Array(5) as _, i (i)}
				<div class="flex items-center gap-3 p-2">
					<Skeleton class="size-4 rounded-full" />
					<div class="flex-1 space-y-1.5">
						<Skeleton class="h-3.5 w-32" />
						<Skeleton class="h-3 w-20" />
					</div>
					<Skeleton class="h-3 w-10" />
				</div>
			{/each}
		</div>
	{:else if (logs.data?.logs ?? []).length === 0}
		<Empty.Root class="py-10">
			<Empty.Header>
				<Empty.Media variant="icon">
					<History />
				</Empty.Media>
				<Empty.Title>No activity yet</Empty.Title>
				<Empty.Description>Workspace events will show up here.</Empty.Description>
			</Empty.Header>
		</Empty.Root>
	{:else}
		<ul class="divide-y">
			{#each logs.data?.logs ?? [] as log (log.id)}
				<li>
					<button
						type="button"
						class="flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-muted/40"
						onclick={() => modal.openWith({ ...log })}
					>
						{#if auditStatusOk(log.statusCode)}
							<CircleCheck class="size-4 shrink-0 text-emerald-500" />
						{:else}
							<CircleX class="size-4 shrink-0 text-destructive" />
						{/if}
						<div class="min-w-0 flex-1">
							<p class="truncate text-sm font-medium">{actionLabel(log.action)}</p>
							<p class="truncate text-xs text-muted-foreground">{actorLabel(log)}</p>
						</div>
						<span class="shrink-0 text-xs whitespace-nowrap text-muted-foreground">
							{formatTs(log.timestamp, 'relative-short')}
						</span>
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>
