<script lang="ts">
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { ExportAuditLogsRequest_Format as Format } from '#lib/gen/nokku/v1/util_pb.js';
	import { Download, type LucideIcon } from '@lucide/svelte';
	import PlanBadge from './PlanBadge.svelte';

	interface Props {
		label?: string;
		/** Says what the file holds. */
		hint: string;
		icon?: LucideIcon;
		pending?: boolean;
		/** The plan feature the export needs. Without it the menu names the plan to buy. */
		feature: string;
		onExport: (format: Format) => void;
	}

	let {
		label = 'Export',
		hint,
		icon: Icon = Download,
		pending = false,
		feature,
		onExport
	}: Props = $props();

	const has = useFeatures();
	const locked = $derived(has(feature) !== true);
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline" disabled={pending}>
				{#if pending}
					<Spinner data-icon="inline-start" />
				{:else}
					<Icon data-icon="inline-start" />
				{/if}
				{label}
				<PlanBadge {feature} />
			</Button>
		{/snippet}
	</DropdownMenu.Trigger>
	<DropdownMenu.Content align="end" class="w-64">
		<DropdownMenu.Group>
			<DropdownMenu.Label class="text-xs font-normal text-muted-foreground"
				>{hint}</DropdownMenu.Label
			>
			<DropdownMenu.Item disabled={locked} onclick={() => onExport(Format.CSV)}>
				CSV, for spreadsheets
			</DropdownMenu.Item>
			<DropdownMenu.Item disabled={locked} onclick={() => onExport(Format.JSON)}>
				JSON, for tooling
			</DropdownMenu.Item>
		</DropdownMenu.Group>
	</DropdownMenu.Content>
</DropdownMenu.Root>
