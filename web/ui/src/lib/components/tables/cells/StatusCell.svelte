<script lang="ts">
	import { Badge } from '$lib/components/ui/badge';
	import { statusTone } from '$lib/tone';

	let { status }: { status: string } = $props();
</script>

<Badge variant={statusTone(status)} class="capitalize">{status}</Badge>
