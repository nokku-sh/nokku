<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';
	import TokenManager from '$lib/components/utils/TokenManager.svelte';
	import { TokenKind } from '$lib/gen/nokku/v1/token_pb';
	import { KeyRound } from '@lucide/svelte';

	const install = 'curl -fsSL https://get.nokku.sh/nokkud | sh';
	// The token is pasted at a no-echo prompt, never passed on the command
	// line where other local users could read it.
	const enroll = 'sudo nokkud --enroll';
</script>

<Dialog.Root>
	<Dialog.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline">
				<KeyRound size={16} />
				Enroll daemons
			</Button>
		{/snippet}
	</Dialog.Trigger>

	<Dialog.Content class="no-scrollbar max-h-[95vh] space-y-4 overflow-y-auto">
		<Dialog.Header>
			<Dialog.Title>Daemon enrollment</Dialog.Title>
			<Dialog.Description>
				Enroll tokens let new nokkud installs join this workspace. One token can enroll a whole
				fleet.
			</Dialog.Description>
		</Dialog.Header>

		<TokenManager kind={TokenKind.ENROLL}>
			{#snippet reveal(secret)}
				<div class="space-y-1.5">
					<p class="text-xs font-medium text-muted-foreground">Token</p>
					<InputGroupVariants variant="copy-input" value={secret} readonly />
				</div>
				<div class="space-y-1.5">
					<p class="text-xs font-medium text-muted-foreground">Install, then enroll</p>
					<InputGroupVariants variant="copy-input" value={install} readonly />
					<InputGroupVariants variant="copy-input" value={enroll} readonly />
				</div>
				<p class="text-xs text-muted-foreground">
					For scripts and Ansible, set <code>NOKKUD_ENROLL_TOKEN</code> in the environment instead of
					answering the prompt.
				</p>
			{/snippet}
		</TokenManager>
	</Dialog.Content>
</Dialog.Root>
