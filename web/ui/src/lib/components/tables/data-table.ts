import { createTableHook } from '@tanstack/svelte-table';
import { features } from './data-table-features.js';

/** App-wide table hooks bound to the shared `features`, so nothing re-passes them. */
export const { createAppTable, createAppColumnHelper } = createTableHook({ features });
