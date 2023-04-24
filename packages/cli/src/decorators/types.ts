import type { Request, Response, RequestHandler } from 'express';
<<<<<<< HEAD
import type { RoleNames, RoleScopes } from '@db/entities/Role';

export type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

export type AuthRole = [RoleScopes, RoleNames] | 'any' | 'none';
export type AuthRoleMetadata = Record<string, AuthRole>;

=======

export type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

>>>>>>> master
export interface MiddlewareMetadata {
	handlerName: string;
}

export interface RouteMetadata {
	method: Method;
	path: string;
	handlerName: string;
	middlewares: RequestHandler[];
}

export type Controller = Record<
	RouteMetadata['handlerName'],
	(req?: Request, res?: Response) => Promise<unknown>
>;
