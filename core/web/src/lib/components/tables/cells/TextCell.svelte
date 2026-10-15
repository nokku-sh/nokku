<script lang="ts">
	let { label }: { label: string } = $props();
</script>

<!-- Prose values. Machine values go in MachineCell. -->
<span class="block max-w-64 truncate text-sm font-medium" title={label}>{label}</span>
