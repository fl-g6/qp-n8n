import config from '@/config';
import type { Request, Response, Application } from 'express';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';

function jwtAuthAuthorizationError(resp: Response, message?: string) {
	resp.statusCode = 403;
	resp.json({ code: resp.statusCode, message });
}

interface QpJwt {
	gcip: {
		x_qp_entitlements: {
			api_roles: string[];
			is_workflow_user_per_service: boolean;
			workflow: string; // n8n User once per tenant
			qp_user_id: string;
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
	const jwtAuthHeader = config.getEnv('security.jwtAuth.jwtHeader');
	if (jwtAuthHeader === '') {
		throw new Error('JWT auth is activated but no request header was defined. Please set one!');
	}

	const jwksUri = config.getEnv('security.jwtAuth.jwksUri');
	if (jwksUri === '') {
		throw new Error('JWT auth is activated but no JWK Set URI was defined. Please set one!');
	}

	const jwtHeaderValuePrefix = config.getEnv('security.jwtAuth.jwtHeaderValuePrefix');
	const jwtIssuer = config.getEnv('security.jwtAuth.jwtIssuer');
	const jwtNamespace = config.getEnv('security.jwtAuth.jwtNamespace');
	const jwtAllowedTenantKey = config.getEnv('security.jwtAuth.jwtAllowedTenantKey');
	const jwtAllowedTenant = config.getEnv('security.jwtAuth.jwtAllowedTenant');

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
				jwtAuthAuthorizationError(res, 'Invalid token');
			} else if (!isTenantAllowed(decoded)) {
				jwtAuthAuthorizationError(res, 'Tenant not allowed');
			} else {
				req.jwt = decoded;
				next();
			}
		});
	});
};
