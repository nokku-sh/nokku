<script lang="ts">
	import { create } from '@bufbuild/protobuf';
	import { daemon as daemonApi } from '$lib/api/daemons.svelte';
	import { Toggle } from '$lib/components/ui/toggle';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { DaemonConfigSchema, type Daemon } from '$lib/gen/nokku/v1/daemon_pb';
	import { toast } from 'svelte-sonner';

	let { daemon }: { daemon: Daemon } = $props();

	const update = daemonApi.update();
	// Shows the new state right away, the refetch after the mutation confirms it.
	let pending = $state<boolean>();
	const on = $derived(pending ?? !!daemon.config?.recordSessions);

	async function toggle(next: boolean) {
		pending = next;
		const config = create(DaemonConfigSchema, daemon.config ?? {});
		config.recordSessions = next;
		try {
			await update.mutateAsync({ id: daemon.id, config });
			toast.success(`Recording ${next ? 'on' : 'off'} for ${daemon.name}`);
		} finally {
			pending = undefined;
		}
	}
</script>

<Tooltip.Root>
	<Tooltip.Trigger>
		{#snippet child({ props })}
			<Toggle
				{...props}
				size="sm"
				variant="outline"
				pressed={on}
				onPressedChange={toggle}
				disabled={update.isPending}
				aria-label={`Session recording for ${daemon.name}`}
				class="h-6 gap-1.5 rounded-full px-2 text-xs data-[state=on]:border-destructive/30 data-[state=on]:bg-destructive/10 data-[state=on]:text-destructive"
			>
				<span class="relative flex size-2">
					{#if on}
						<span class="absolute inline-flex size-full animate-ping rounded-full bg-destructive/60"
						></span>
						<span class="relative size-2 rounded-full bg-destructive"></span>
					{:else}
						<span class="relative size-2 rounded-full border border-muted-foreground/50"></span>
					{/if}
				</span>
				{on ? 'REC' : 'Off'}
			</Toggle>
		{/snippet}
	</Tooltip.Trigger>
	<Tooltip.Content>
		{on ? 'Recording new sessions. Click to stop.' : 'Not recording. Click to start.'}
	</Tooltip.Content>
</Tooltip.Root>
