<script lang="ts">
	import { util } from '#lib/api/workspaces.svelte.js';
	import ExportMenu from '#lib/components/blocks/ExportMenu.svelte';
	import { ClipboardCheck } from '@lucide/svelte';

	const exportReport = util.exportAccessReport();
</script>

<ExportMenu
	label="Access report"
	hint="Who can log in where, and when they last got a certificate there. Grants unused for 90 days are marked stale."
	icon={ClipboardCheck}
	feature="access_review"
	pending={exportReport.isPending}
	onExport={(format) => exportReport.mutate({ format })}
/>
