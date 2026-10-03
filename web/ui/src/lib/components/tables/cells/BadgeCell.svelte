<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';

	type Props = {
		value: string;
	};
	let { value = $bindable(''), ...restProps }: Props = $props();
</script>

<Badge {...restProps}>
	{value}
</Badge>
