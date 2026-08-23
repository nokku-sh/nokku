import { createTableHook } from '@tanstack/svelte-table';
import { features } from './data-table-features.js';

/**
 * App-wide table hooks bound to the shared `features`. Pages use
 * `createAppColumnHelper` to build type-safe columns and `DataTable` uses
 * `createAppTable` to create the table without re-passing `features`.
 */
export const { createAppTable, createAppColumnHelper } = createTableHook({ features });
