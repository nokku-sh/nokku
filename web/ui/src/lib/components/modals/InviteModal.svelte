<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog/';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';
	import TokenManager from '$lib/components/utils/TokenManager.svelte';
	import { TokenKind } from '$lib/gen/nokku/v1/token_pb';
	import { Users } from '@lucide/svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="no-scrollbar max-h-[95vh] space-y-4 overflow-y-auto">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<Users size={20} />
				Invite members
			</Dialog.Title>
			<Dialog.Description>
				Anyone with an invite link can join with its role until it expires or runs out of uses.
			</Dialog.Description>
		</Dialog.Header>

		<TokenManager kind={TokenKind.INVITE}>
			{#snippet reveal(secret)}
				<div class="space-y-1.5">
					<p class="text-xs font-medium text-muted-foreground">Invitation link</p>
					<InputGroupVariants
						variant="copy-input"
						value={`${location.origin}/?invite=${secret}`}
						readonly
					/>
				</div>
			{/snippet}
		</TokenManager>
	</Dialog.Content>
</Dialog.Root>
