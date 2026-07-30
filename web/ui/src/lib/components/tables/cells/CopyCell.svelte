<script lang="ts">
	import { CopyButton } from '$lib/components/ui/copy-button';

	type Props = {
		value: string;
	};
	let { value, ...restProps }: Props = $props();
</script>

<span class="truncate text-xs text-muted-foreground" title={value} {...restProps}>
	<CopyButton text={value} icon={false} class="p-0 hover:bg-transparent">
		<span class="font-mono text-sm font-light">{value}</span>
	</CopyButton>
</span>
