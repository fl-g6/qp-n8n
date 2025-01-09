<<<<<<< HEAD
import type { IMenuItem, RouteObject } from '@/types';
import type { RouteLocationRaw } from 'vue-router';
=======
import type { RouteLocationNormalizedLoaded, RouteLocationRaw } from 'vue-router';

import type { IMenuItem } from 'n8n-design-system/types';
>>>>>>> tags/n8n@1.74.1

/**
 * Checks if the given menu item matches the current route.
 */
<<<<<<< HEAD
export function doesMenuItemMatchCurrentRoute(item: IMenuItem, currentRoute: RouteObject) {
=======
export function doesMenuItemMatchCurrentRoute(
	item: IMenuItem,
	currentRoute: RouteLocationNormalizedLoaded,
) {
>>>>>>> tags/n8n@1.74.1
	let activateOnRouteNames: string[] = [];
	if (Array.isArray(item.activateOnRouteNames)) {
		activateOnRouteNames = item.activateOnRouteNames;
	} else if (item.route && isNamedRouteLocation(item.route.to)) {
		activateOnRouteNames = [item.route.to.name];
	}

	let activateOnRoutePaths: string[] = [];
	if (Array.isArray(item.activateOnRoutePaths)) {
		activateOnRoutePaths = item.activateOnRoutePaths;
	} else if (item.route && isPathRouteLocation(item.route.to)) {
		activateOnRoutePaths = [item.route.to.path];
	}

	return (
<<<<<<< HEAD
		activateOnRouteNames.includes(currentRoute.name ?? '') ||
=======
		activateOnRouteNames.includes((currentRoute.name as string) ?? '') ||
>>>>>>> tags/n8n@1.74.1
		activateOnRoutePaths.includes(currentRoute.path)
	);
}

function isPathRouteLocation(routeLocation?: RouteLocationRaw): routeLocation is { path: string } {
	return (
		typeof routeLocation === 'object' &&
		'path' in routeLocation &&
		typeof routeLocation.path === 'string'
	);
}

function isNamedRouteLocation(routeLocation?: RouteLocationRaw): routeLocation is { name: string } {
	return (
		typeof routeLocation === 'object' &&
		'name' in routeLocation &&
		typeof routeLocation.name === 'string'
	);
}
