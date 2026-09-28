<script lang="ts">
	import { CircleCheckBig, CircleX } from '@lucide/svelte';
	import type { JsonValue } from '@bufbuild/protobuf';
	import * as Dialog from '$lib/components/ui/dialog/';
	import { Badge } from '$lib/components/ui/badge';
	import CopyButton from '$lib/components/ui/copy-button/copy-button.svelte';
	import { Label } from '$lib/components/ui/label';
	import type { EventLog } from '$lib/gen/nokku/v1/util_pb';
	import { actionLabel, formatTs } from '$lib/utils';

	interface Props {
		log: EventLog;
		open?: boolean;
	}
	let { log = $bindable(), open = $bindable(false) }: Props = $props();

	const detailEntries = $derived(Object.entries(log.details ?? {}));

	function detailValue(v: JsonValue | null): string {
		if (typeof v === 'string') return v;
		return JSON.stringify(v);
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="no-scrollbar max-h-[95vh] min-w-150 overflow-y-auto">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				{#if log.ok}
					<CircleCheckBig class="size-4 text-emerald-500" />
				{:else}
					<CircleX class="size-4 text-destructive" />
				{/if}
				{actionLabel(log.action)}
			</Dialog.Title>
			<Dialog.Description>
				{formatTs(log.timestamp, 'withTime')} · {formatTs(log.timestamp, 'relative')}
			</Dialog.Description>
		</Dialog.Header>

		<div class="space-y-4">
			<!-- Actor -->
			<div class="space-y-2">
				<Label class="text-sm font-semibold">Actor</Label>
				<div
					class="grid gap-x-4 gap-y-3 rounded-lg border bg-muted/30 p-4 sm:grid-cols-[auto_1fr] sm:items-center"
				>
					<div class="space-y-0.5">
						<p class="text-xs text-muted-foreground">Name</p>
						{#if log.actorName}
							<p class="font-mono text-sm">{log.actorName}</p>
						{:else}
							<span class="text-xs text-muted-foreground italic">unknown</span>
						{/if}
					</div>
					<div class="flex items-center gap-2 sm:justify-end">
						<Badge variant="secondary" class="capitalize">{log.actorKind || 'unknown'}</Badge>
						{#if !log.ok}
							<Badge variant="destructive">Failed</Badge>
						{/if}
					</div>
					{#if log.actorId}
						<div class="space-y-0.5 sm:col-span-2">
							<p class="text-xs text-muted-foreground">ID</p>
							<CopyButton text={log.actorId} icon={false} class="h-auto p-0">
								<span class="font-mono text-xs text-muted-foreground">{log.actorId}</span>
							</CopyButton>
						</div>
					{/if}
				</div>
			</div>

			{#if log.target}
				<div class="space-y-2">
					<Label class="text-sm font-semibold">Target</Label>
					<div class="rounded-lg border bg-muted/30 p-4">
						<CopyButton text={log.target} icon={false} class="h-auto p-0">
							<span class="font-mono text-sm">{log.target}</span>
						</CopyButton>
					</div>
				</div>
			{/if}

			<!-- Source -->
			<div class="space-y-2">
				<Label class="text-sm font-semibold">Source</Label>
				<div class="grid gap-2 rounded-lg border bg-muted/30 p-4">
					<div class="space-y-1">
						<p class="text-xs text-muted-foreground">IP Address</p>
						<p class="font-mono text-sm">{log.ip || 'N/A'}</p>
					</div>
					{#if log.userAgent}
						<div class="space-y-1">
							<p class="text-xs text-muted-foreground">User Agent</p>
							<p class="font-mono text-xs break-all text-muted-foreground">
								{log.userAgent}
							</p>
						</div>
					{/if}
				</div>
			</div>

			<!-- Details -->
			{#if detailEntries.length > 0}
				<div class="space-y-2">
					<Label class="text-sm font-semibold">Details</Label>
					<div class="divide-y rounded-lg border bg-muted/30 px-4">
						{#each detailEntries as [key, value] (key)}
							<div class="flex items-baseline justify-between gap-4 py-2.5 first:border-t-0">
								<span class="text-xs text-muted-foreground capitalize">{key}</span>
								<span
									class="max-w-60 truncate text-right font-mono text-sm"
									title={detailValue(value)}
								>
									{detailValue(value)}
								</span>
							</div>
						{/each}
					</div>
				</div>
			{/if}
		</div>
	</Dialog.Content>
</Dialog.Root>
