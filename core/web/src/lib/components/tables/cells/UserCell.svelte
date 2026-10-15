<script lang="ts">
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import type { User } from '#lib/gen/nokku/v1/account_pb.js';

	let { user }: { user: User } = $props();

	const name = $derived(user.name || user.email.split('@')[0]);
</script>

<div class="flex min-w-0 items-center gap-3">
	<UserAvatar {user} />
	<!-- No clipping wrapper around the copy button, its focus ring needs the room. -->
	<div class="flex min-w-0 flex-col items-start">
		<span class="max-w-full truncate text-sm font-medium" title={name}>{name}</span>
		<CopyText
			value={user.email}
			mono
			class="max-w-none text-muted-foreground underline decoration-muted-foreground/40 decoration-dotted underline-offset-2 hover:text-foreground"
		/>
	</div>
</div>
