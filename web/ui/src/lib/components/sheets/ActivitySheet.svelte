<script lang="ts">
	import { eventLabel, outcomeLabel, outcomeOf } from '#lib/components/audit/audit.js';
	import type { JsonValue } from '@bufbuild/protobuf';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import type { EventLog } from '#lib/gen/nokku/v1/util_pb.js';
	import { formatTs } from '#lib/utils.js';
	import { CircleCheckBig, CircleX, Globe, UserRound, Zap } from '@lucide/svelte';
	import DetailList from './DetailList.svelte';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	interface Props {
		log?: EventLog;
		onClose: () => void;
	}

	let { log, onClose }: Props = $props();

	const actorHref = $derived.by(() => {
		if (!log?.actorId) return undefined;
		if (log.actorKind === 'user') return `/access/users?id=${log.actorId}`;
		if (log.actorKind === 'service_account') return `/access/service-accounts?id=${log.actorId}`;
		return undefined;
	});

	const details = $derived(
		Object.entries(log?.details ?? {}).map(([key, value]) => ({
			label: key.replace(/[-_]/g, ' '),
			value: detailValue(value),
			mono: true
		}))
	);

	function detailValue(v: JsonValue | null): string {
		return typeof v === 'string' ? v : JSON.stringify(v);
	}
</script>

<EntitySheet open={!!log} {onClose} title={log ? eventLabel(log.action) : ''}>
	{#snippet media()}
		<div
			class={[
				'flex size-10 items-center justify-center rounded-lg',
				log?.ok ? 'bg-success/10 text-success' : 'bg-destructive/10 text-destructive'
			]}
		>
			{#if log?.ok}<CircleCheckBig class="size-5" />{:else}<CircleX class="size-5" />{/if}
		</div>
	{/snippet}

	{#snippet subtitle()}
		<span>{formatTs(log?.timestamp, 'withTime')}</span>
		<span>· {formatTs(log?.timestamp, 'relative')}</span>
		{#if log && !log.ok}<Badge variant="destructive">{outcomeLabel[outcomeOf(log)]}</Badge>{/if}
	{/snippet}

	{#if log}
		<div class="flex flex-col divide-y">
			<Section title="Who" icon={UserRound}>
				<DetailList
					items={[
						{ label: 'Name', value: log.actorName || 'unknown', href: actorHref },
						{ label: 'Kind', value: log.actorKind.replace(/_/g, ' ') || 'unknown' },
						{ label: 'Actor ID', value: log.actorId, mono: true, copy: true, wide: true }
					]}
				/>
			</Section>
			<Section title="What" icon={Zap}>
				<DetailList
					items={[
						{ label: 'Action', value: log.action, mono: true },
						{ label: 'Target', value: log.target, mono: true, copy: true, wide: true },
						...details
					]}
				/>
			</Section>
			<Section title="From" icon={Globe}>
				<DetailList
					items={[
						{ label: 'IP address', value: log.ip || 'unknown', mono: true, copy: !!log.ip },
						{ label: 'Event ID', value: log.id, mono: true, copy: true, wide: true },
						{ label: 'User agent', value: log.userAgent, mono: true, wide: true }
					]}
				/>
			</Section>
		</div>
	{/if}
</EntitySheet>
