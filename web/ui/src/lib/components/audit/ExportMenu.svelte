<script lang="ts">
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { util } from '#lib/api/workspaces.svelte.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import {
		ExportAuditLogsRequest_Format as Format,
		type AuditLogFilter
	} from '#lib/gen/nokku/v1/util_pb.js';
	import { Download } from '@lucide/svelte';

	interface Props {
		/** The same filter the page shows, so the export matches the screen. */
		filter: Partial<Omit<AuditLogFilter, '$typeName'>>;
		/** Empty exports the caller's own events across workspaces. */
		workspaceId?: string;
	}

	let { filter, workspaceId }: Props = $props();

	const exportLogs = util.exportLogs();

	// Exports need both bounds, an open ended range ends now.
	function exportAs(format: Format) {
		exportLogs.mutate({
			format,
			workspaceId,
			filter: { ...filter, endDate: filter.endDate ?? timestampFromDate(new Date()) }
		});
	}
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline" disabled={exportLogs.isPending}>
				{#if exportLogs.isPending}
					<Spinner data-icon="inline-start" />
				{:else}
					<Download data-icon="inline-start" />
				{/if}
				Export
			</Button>
		{/snippet}
	</DropdownMenu.Trigger>
	<DropdownMenu.Content align="end" class="w-60">
		<DropdownMenu.Group>
			<DropdownMenu.Label class="text-xs font-normal text-muted-foreground">
				Exactly what is on screen, up to 90 days
			</DropdownMenu.Label>
			<DropdownMenu.Item onclick={() => exportAs(Format.CSV)}
				>CSV, for spreadsheets</DropdownMenu.Item
			>
			<DropdownMenu.Item onclick={() => exportAs(Format.JSON)}>JSON, for tooling</DropdownMenu.Item>
		</DropdownMenu.Group>
	</DropdownMenu.Content>
</DropdownMenu.Root>
