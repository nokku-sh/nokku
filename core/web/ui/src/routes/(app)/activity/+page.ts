import { redirect } from '@sveltejs/kit';

// The audit log used to live here, old links and bookmarks keep working.
export const load = ({ url }) => {
	throw redirect(307, `/audit${url.search}`);
};
