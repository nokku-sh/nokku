<script lang="ts">
	import { CopyButton } from '$lib/components/ui/copy-button';
	import UserAvatar from '$lib/components/utils/UserAvatar.svelte';
	import type { User } from '$lib/gen/nokku/v1/user_pb';
	import type { WorkspaceMember } from '$lib/gen/nokku/v1/workspace_pb';

	type Props = {
		user: User | WorkspaceMember;
	};
	let { user, ...restProps }: Props = $props();
</script>

<div class="flex items-center gap-3" {...restProps}>
	<UserAvatar {user} />
	<div class="flex flex-col">
		<span class="truncate text-sm font-medium" title={user.name}>{user.name}</span>
		<span class="truncate text-xs text-muted-foreground" title={user.email}>
			<CopyButton text={user.email} icon={false} class="p-0 hover:bg-transparent">
				<span class="font-mono text-sm font-light">{user.email}</span>
			</CopyButton>
		</span>
	</div>
</div>
