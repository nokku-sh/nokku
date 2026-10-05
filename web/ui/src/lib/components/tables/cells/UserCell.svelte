<script lang="ts">
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import type { User } from '#lib/gen/nokku/v1/account_pb.js';
	import type { WorkspaceMember } from '#lib/gen/nokku/v1/workspace_pb.js';

	type Props = {
		user: User | WorkspaceMember;
	};
	let { user, ...restProps }: Props = $props();

	const name = $derived(user.name || user.email.split('@')[0]);
</script>

<div class="flex items-center gap-3" {...restProps}>
	<UserAvatar {user} />
	<div class="flex flex-col">
		<span class="truncate text-sm font-medium" title={name}>{name}</span>
		<span class="truncate text-xs text-muted-foreground" title={user.email}>
			<CopyText value={user.email} mono />
		</span>
	</div>
</div>
