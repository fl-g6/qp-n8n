import type { Request, Response, Application } from 'express';
import jwt = require('jsonwebtoken');
import jwks = require('jwks-rsa');
import {
	JWT_JWKS_URI,
	JWT_ALLOWED_TENANT,
	JWT_ALLOWED_TENANT_KEY,
	JWT_AUTH_HEADER,
	JWT_AUTH_HEADER_VALUE_PREFIX,
	JWT_ISSUER,
	JWT_NAMESPACE,
} from 'n8n-core';
import { ApplicationError } from 'n8n-workflow';

export function jwtAuthAuthorizationError(resp: Response, message?: string) {
	resp.statusCode = 403;
	resp.json({ code: resp.statusCode, message });
}

export interface QpJwt extends jwt.JwtPayload {
	gcip: {
		x_qp_entitlements: {
			api_roles: string[];
			is_workflow_user_per_service?: boolean;
			workflow: string; // n8n User once per tenant
			qp_user_id?: string;
			service_id: string;
			// allowed_products: Array<{
			// 	datastudio: string;
			// 	product_id: string;
			// 	storefront: string;
			// 	workflow: string; // n8n User
			// }>;
			//is_super_admin: boolean;
			//is_service_admin: boolean;
		};
	};
}

export interface QpJwtRequest<
	RouteParams = {},
	ResponseBody = {},
	RequestBody = {},
	RequestQuery = {},
> extends Request<RouteParams, ResponseBody, RequestBody, RequestQuery> {
	jwt: QpJwt;
}

export const setupExternalJWTAuth = (app: Application, authIgnoreRegex: RegExp) => {
	const jwtAuthHeader = process.env[JWT_AUTH_HEADER] ?? '';
	if (jwtAuthHeader === '') {
		throw new ApplicationError(
			'JWT auth is activated but no request header was defined. Please set one!',
		);
	}

	const jwksUri = process.env[JWT_JWKS_URI] ?? '';
	if (jwksUri === '') {
		throw new ApplicationError(
			'JWT auth is activated but no JWK Set URI was defined. Please set one!',
		);
	}

	const jwtHeaderValuePrefix = process.env[JWT_AUTH_HEADER_VALUE_PREFIX] ?? '';
	const jwtIssuer = process.env[JWT_ISSUER] ?? '';
	const jwtNamespace = process.env[JWT_NAMESPACE] ?? '';
	const jwtAllowedTenantKey = process.env[JWT_ALLOWED_TENANT_KEY] ?? '';
	const jwtAllowedTenant = process.env[JWT_ALLOWED_TENANT] ?? '';

	// eslint-disable-next-line no-inner-declarations
	function isTenantAllowed(decodedToken: object): boolean {
		if (jwtNamespace === '' || jwtAllowedTenantKey === '' || jwtAllowedTenant === '') {
			return true;
		}

		for (const [k, v] of Object.entries(decodedToken)) {
			if (k === jwtNamespace) {
				// eslint-disable-next-line @typescript-eslint/no-unsafe-argument
				for (const [kn, kv] of Object.entries(v)) {
					if (kn === jwtAllowedTenantKey && kv === jwtAllowedTenant) {
						return true;
					}
				}
			}
		}

		return false;
	}

	// eslint-disable-next-line consistent-return
	app.use((req: QpJwtRequest, res, next) => {
		if (authIgnoreRegex.exec(req.url)) {
			return next();
		}

		let token = req.header(jwtAuthHeader) as string;
		if (token === undefined || token === '') {
			return jwtAuthAuthorizationError(res, 'Missing token');
		}

		if (jwtHeaderValuePrefix !== '' && token.startsWith(jwtHeaderValuePrefix)) {
			token = token.replace(`${jwtHeaderValuePrefix} `, '').trimStart();
		}

		const jwkClient = jwks({ cache: true, jwksUri });
		const getKey: jwt.GetPublicKeyOrSecret = (header, callbackFn) => {
			// eslint-disable-next-line @typescript-eslint/no-throw-literal
			if (!header.kid) throw jwtAuthAuthorizationError(res, 'No JWT key found');
			jwkClient.getSigningKey(header.kid, (error, key) => {
				// eslint-disable-next-line @typescript-eslint/no-throw-literal
				if (error) throw jwtAuthAuthorizationError(res, error.message);
				callbackFn(null, key?.getPublicKey());
			});
		};

		const jwtVerifyOptions: jwt.VerifyOptions = {
			issuer: jwtIssuer !== '' ? jwtIssuer : undefined,
			ignoreExpiration: false,
		};

		jwt.verify(token, getKey, jwtVerifyOptions, (error: jwt.VerifyErrors, decoded: QpJwt) => {
			if (error) {
				jwtAuthAuthorizationError(res, 'Invalid token error');
			} else if (!isTenantAllowed(decoded)) {
				jwtAuthAuthorizationError(res, 'Tenant not allowed');
			} else {
				req.jwt = decoded;
				next();
			}
		});
	});
};
