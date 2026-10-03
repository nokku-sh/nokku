<script lang="ts">
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import type { User } from '#lib/gen/nokku/v1/account_pb.js';
	import type { WorkspaceMember } from '#lib/gen/nokku/v1/workspace_pb.js';

	type Props = {
		user: User | WorkspaceMember;
	};
	let { user, ...restProps }: Props = $props();
</script>

<div class="flex items-center gap-3" {...restProps}>
	<UserAvatar {user} />
	<div class="flex flex-col">
		{#if user.name}
			<span class="truncate text-sm font-medium" title={user.name}>{user.name}</span>
		{:else}
			<span class="truncate text-sm font-medium" title={user.email.split('@')[0]}>
				{user.email.split('@')[0]}
			</span>
		{/if}
		<span class="truncate text-xs text-muted-foreground" title={user.email}>
			<CopyText value={user.email} mono />
		</span>
	</div>
</div>
