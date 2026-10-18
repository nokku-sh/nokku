<script lang="ts">
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { requiredPlan } from '#lib/plans.js';

	/** Names the plan to buy while the workspace's plan lacks the feature. */
	let { feature }: { feature: string } = $props();

	const has = useFeatures();
</script>

{#if has(feature) === false}
	<Badge variant="outline">{requiredPlan(feature)}</Badge>
{/if}
