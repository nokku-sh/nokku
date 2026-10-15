<script lang="ts">
	import { plural } from '#lib/api/bulk.js';

	let { memberCount = 0 }: { memberCount?: number } = $props();
</script>

<span class={['text-sm tabular-nums', !memberCount && 'text-muted-foreground']}>
	{memberCount ? plural(memberCount, 'member') : 'No members'}
</span>
