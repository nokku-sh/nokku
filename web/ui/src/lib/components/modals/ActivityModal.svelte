<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog/';
	import { Label } from '$lib/components/ui/label';
	import type { EventLog } from '$lib/gen/nokku/v1/util_pb';
	import { formatTs } from '$lib/utils';
	import { CircleCheckBig, CircleX } from '@lucide/svelte';

	interface Props {
		log: EventLog;
		open?: boolean;
	}
	let { log = $bindable(), open = $bindable(false) }: Props = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="no-scrollbar max-h-[95vh] min-w-150 overflow-y-auto">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				{#if log.statusCode === ''}
					<CircleCheckBig class="text-green-500" size={16} />
				{:else}
					<CircleX class="text-red-500" size={16} />
				{/if}
				Details
			</Dialog.Title>
			<Dialog.Description>
				<span class="text-primary capitalize">{log.action} •</span>
				{formatTs(log.timestamp, 'relative')}
			</Dialog.Description>
		</Dialog.Header>

		<div class="space-y-4">
			<!-- Source Section -->
			<div class="space-y-2">
				<Label class="text-sm font-semibold">Source</Label>
				<div class="grid gap-2 rounded-lg border bg-muted/30 p-4">
					<div class="flex items-center justify-between">
						<div class="space-y-1">
							<p class="text-xs text-muted-foreground">IP Address</p>
							<p class="font-mono text-sm">{log.ipAddress || 'N/A'}</p>
						</div>
					</div>
					{#if log.userAgent}
						<div class="space-y-1">
							<p class="text-xs text-muted-foreground">User Agent</p>
							<p class="font-mono text-xs text-muted-foreground">
								{log.userAgent}
							</p>
						</div>
					{/if}
				</div>
			</div>
		</div>
	</Dialog.Content>
</Dialog.Root>
