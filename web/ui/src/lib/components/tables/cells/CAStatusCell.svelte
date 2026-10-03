<script lang="ts">
	import { ca } from '#lib/api/certificates.svelte.js';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import type { CertificateAuthority } from '#lib/gen/nokku/v1/certificates_pb.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import { ShieldCheck, ShieldOff } from '@lucide/svelte';

	interface Props {
		caItem: CertificateAuthority;
	}

	let { caItem }: Props = $props();

	let enabled = $derived(caItem.isActive);

	const updateCA = ca.update();
	function handleStatusChange(val: string) {
		const isActive = val === 'active';
		if (isActive === enabled) return;

		updateCA.mutate({ ...caItem, isActive });
	}
</script>

<Select.Root
	type="single"
	value={enabled ? 'active' : 'inactive'}
	onValueChange={handleStatusChange}
>
	<Select.Trigger
		disabled={updateCA.isPending}
		class="h-auto! w-fit cursor-pointer justify-center gap-1.5 rounded-full border-none bg-transparent! px-2.5 py-0.5 text-xs font-medium transition-all focus:ring-0 disabled:opacity-70 [&>svg:last-child]:hidden"
	>
		{#if updateCA.isPending}
			<Spinner class="size-3 text-muted-foreground" />
			<span class="text-muted-foreground">Updating&hellip;</span>
		{:else if enabled}
			<Badge variant="success">Active</Badge>
		{:else}
			<Badge variant="destructive">Inactive</Badge>
		{/if}
	</Select.Trigger>

	<Select.Content class="w-48">
		<Select.Group>
			<Select.Item value="active" label="Active" class="cursor-pointer items-center gap-2.5 py-2">
				<div class="flex size-5 shrink-0 items-center justify-center rounded-full text-success">
					<ShieldCheck />
				</div>
				<div class="flex flex-col text-left">
					<span class="text-xs font-medium">Active</span>
					<span class="text-2xs text-muted-foreground">Enable CA for signing</span>
				</div>
			</Select.Item>

			<Select.Item
				value="inactive"
				label="Inactive"
				class="cursor-pointer items-center gap-2.5 py-2"
			>
				<div class="flex size-5 shrink-0 items-center justify-center rounded-full text-destructive">
					<ShieldOff />
				</div>
				<div class="flex flex-col text-left">
					<span class="text-xs font-medium">Inactive</span>
					<span class="text-2xs text-muted-foreground">Disable signing</span>
				</div>
			</Select.Item>
		</Select.Group>
	</Select.Content>
</Select.Root>
