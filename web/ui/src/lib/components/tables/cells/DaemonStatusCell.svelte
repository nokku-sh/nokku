<script lang="ts">
	import { daemon as daemonApi } from '$lib/api/daemons.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { Spinner } from '$lib/components/ui/spinner';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { DaemonStatus, type Daemon } from '$lib/gen/nokku/v1/daemon_pb';
	import { confirm } from '$lib/hooks';
	import { Check, CircleCheck, Clock, X } from '@lucide/svelte';

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

{#if daemon.status === DaemonStatus.PENDING}
	<div class="flex items-center gap-1">
		<Badge variant="warning"><Clock data-icon="inline-start" />Pending</Badge>
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
	</div>
{:else}
	<Badge variant="success"><CircleCheck data-icon="inline-start" />Accepted</Badge>
{/if}
