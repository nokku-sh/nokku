<script lang="ts">
	import { missedRollover } from '#lib/api/certificates.svelte.js';
	import { useDaemonReview } from '#lib/api/daemons.svelte.js';
	import { user } from '#lib/api/user.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { StateCell } from '#lib/components/tables/cells/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { DaemonStatus } from '#lib/gen/nokku/v1/daemon_pb.js';
	import type { Target } from '#lib/gen/nokku/v1/target_pb.js';
	import { formatTs } from '#lib/utils.js';
	import type { Timestamp } from '@bufbuild/protobuf/wkt';
	import { Ban, Check, Clock, RefreshCw, TriangleAlert, Wifi, WifiOff, X } from '@lucide/svelte';

	interface Props {
		target: Target;
		/** When the CA last rolled over. A server synced before that refuses new certificates. */
		caRotatedAt?: Timestamp;
	}

	let { target, caRotatedAt }: Props = $props();

	const can = user.can();
	const review = useDaemonReview();
	const d = $derived(target.daemon);
	const pending = $derived(d?.status === DaemonStatus.PENDING);
	const stale = $derived(!d && missedRollover(caRotatedAt, target.lastSyncAt));

	// The line under the badge: how fresh the state is, and the daemon's version where there is one.
	const detail = $derived.by(() => {
		if (!d) {
			if (stale) return 'Run nk sync, the CA rolled over since';
			return target.lastSyncAt
				? `Synced ${formatTs(target.lastSyncAt, 'relative')}`
				: 'Not synced yet';
		}
		if (d.status !== DaemonStatus.ACCEPTED) return `Enrolled ${formatTs(d.createdAt, 'relative')}`;
		const version = d.version && `nokkud ${d.version}`;
		if (d.behindSince) return `Since ${formatTs(d.behindSince, 'relative')}`;
		if (d.online) return version;
		const seen = d.lastSeenAt
			? `Last seen ${formatTs(d.lastSeenAt, 'relative')}`
			: 'Never connected';
		return [seen, version].filter(Boolean).join(' · ');
	});
</script>

<div class="flex flex-col items-start gap-0.5">
	{@render state()}
	{#if detail}
		<span class="text-xs text-muted-foreground">{detail}</span>
	{/if}
</div>

{#snippet state()}
	{#if !d}
		{#if stale}
			<StateCell label="Behind the CA" tone="warning" icon={TriangleAlert} />
		{:else}
			<StateCell label="nk sync" tone="muted" icon={RefreshCw} />
		{/if}
	{:else if d.status === DaemonStatus.ACCEPTED}
		<div class="flex items-center gap-1">
			<StateCell
				label={d.behindSince ? 'Behind' : d.online ? 'Online' : 'Offline'}
				icon={d.behindSince ? TriangleAlert : d.online ? Wifi : WifiOff}
			/>
			{#if d.config?.recordSessions}
				<Badge variant="destructive" title="Sessions here are recorded">REC</Badge>
			{/if}
		</div>
	{:else}
		<!-- Anything but accepted keeps people out, so every such state offers Approve. -->
		<div class="flex items-center gap-1">
			{#if pending}
				<Badge variant="warning"><Clock data-icon="inline-start" />Needs approval</Badge>
			{:else}
				<Badge variant="destructive"><Ban data-icon="inline-start" />Rejected</Badge>
			{/if}
			{#if can.edit}
				<Button
					size="xs"
					variant="outline"
					disabled={review.pending}
					onclick={() => review.approve(d)}
				>
					{#if review.approving(d.id)}<Spinner data-icon="inline-start" />{:else}<Check
							data-icon="inline-start"
						/>{/if}
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
									aria-label={`Reject ${d.name}`}
									onclick={() => review.reject(d)}
								>
									<X />
								</Button>
							{/snippet}
						</Tooltip.Trigger>
						<Tooltip.Content>Reject</Tooltip.Content>
					</Tooltip.Root>
				{/if}
			{/if}
		</div>
	{/if}
{/snippet}
