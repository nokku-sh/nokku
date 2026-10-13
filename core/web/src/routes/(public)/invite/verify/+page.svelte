<script lang="ts">
	import ConsumeLink from '#lib/components/blocks/ConsumeLink.svelte';
</script>

<!-- A new account has only the mailed link, so it lands where it can add a passkey. -->
<ConsumeLink
	title="Creating your account"
	retryHref="/login"
	retryLabel="Back to sign in"
	next="/profile/security"
/>
