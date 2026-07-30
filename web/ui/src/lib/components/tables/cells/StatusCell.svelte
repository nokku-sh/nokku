<script lang="ts">
	import { Badge, type BadgeVariant } from '$lib/components/ui/badge';

	type Props = {
		status: string;
	};
	let { status, ...restProps }: Props = $props();

	// Map common status strings to shadcn variants
	let variant = $derived.by(() => {
		const s = status.toLowerCase();
		if (['active', 'online', 'success', 'completed'].includes(s)) return 'default';
		if (['error', 'failed', 'offline', 'inactive'].includes(s)) return 'destructive';
		if (['warning', 'flagged', 'pending'].includes(s)) return 'outline';
		return 'secondary'; // pending, inactive, draft, etc.
	}) as BadgeVariant;
</script>

<div {...restProps}>
	<Badge {variant} class="capitalize">
		{status}
	</Badge>
</div>
