<script lang="ts">
	import { daemon as daemonApi } from '#lib/api/daemons.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { DaemonStatus, type Daemon } from '#lib/gen/nokku/v1/daemon_pb.js';
	import { confirm } from '#lib/hooks/index.js';
	import { Ban, Check, CircleCheck, Clock, X } from '@lucide/svelte';

	let { daemon }: { daemon: Daemon } = $props();

	const update = daemonApi.update();
	const remove = daemonApi.delete();

	function reject() {
		void confirm({
			title: `Reject ${daemon.name}?`,
			description: 'The daemon is removed and has to enroll again.',
			confirmText: 'Reject',
			onConfirm: () => remove.mutateAsync({ id: daemon.id })
		});
	}
</script>

<!-- Anything but accepted keeps the daemon out, so every such state offers Approve. -->
{#if daemon.status === DaemonStatus.ACCEPTED}
	<Badge variant="success"><CircleCheck data-icon="inline-start" />Accepted</Badge>
{:else}
	{@const pending = daemon.status === DaemonStatus.PENDING}
	<div class="flex items-center gap-1">
		{#if pending}
			<Badge variant="warning"><Clock data-icon="inline-start" />Pending</Badge>
		{:else}
			<Badge variant="destructive">
				<Ban data-icon="inline-start" />
				{daemon.status === DaemonStatus.REJECTED ? 'Rejected' : 'Not accepted'}
			</Badge>
		{/if}
		<Button
			size="xs"
			disabled={update.isPending}
			onclick={() => update.mutate({ id: daemon.id, status: DaemonStatus.ACCEPTED })}
		>
			{#if update.isPending}
				<Spinner data-icon="inline-start" />
			{:else}
				<Check data-icon="inline-start" />
			{/if}
			Approve
		</Button>
		{#if pending}
			<Tooltip.Root>
				<Tooltip.Trigger>
					{#snippet child({ props })}
						<Button
							{...props}
							size="icon-xs"
							variant="ghost"
							aria-label={`Reject ${daemon.name}`}
							onclick={reject}
						>
							<X />
						</Button>
					{/snippet}
				</Tooltip.Trigger>
				<Tooltip.Content>Reject</Tooltip.Content>
			</Tooltip.Root>
		{/if}
	</div>
{/if}
