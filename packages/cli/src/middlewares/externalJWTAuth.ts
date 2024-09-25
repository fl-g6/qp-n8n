import config from '@/config';
import { type Request, type Response, type Application, json } from 'express';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import * as jose from 'jose'
import axios from 'axios';

const awsCognitoPubKey = new Map<string, jose.KeyLike>();

function jwtAuthAuthorizationError(resp: Response, message?: string) {
	resp.statusCode = 403;
	resp.json({ code: resp.statusCode, message });
}

interface QpJwt {
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

	const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));

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
	app.use(async (req: QpJwtRequest, res, next) => {
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

		// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#user-claims-encoding
		if (process.env.PROVIDER === 'AWS') {
			try {
				const alg = 'ES256';
				const jwt_headers = token.split('.')[0];
				const decoded_jwt_headers = Buffer.from(jwt_headers, 'base64').toString('utf-8');
				// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
				const jwtJson = JSON.parse(decoded_jwt_headers);
				// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/dot-notation
				const kid: string = jwtJson['kid'] as string;
				if (!awsCognitoPubKey.has(kid)) {
					const pubKeyUrl =
						'https://public-keys.auth.elb.' + process.env.AWS_REGION + '.amazonaws.com/' + kid;
					const pubKeyRes = await axios.get(pubKeyUrl);
					console.log('public key url %s', pubKeyUrl);
					console.log('public key %s', pubKeyRes.data);
					const publicKeyTmp = await jose.importSPKI(pubKeyRes.data as string, alg);
					awsCognitoPubKey.set(kid, publicKeyTmp);
				}
				const pubKey = awsCognitoPubKey.get(kid);
				if (pubKey === undefined) {
					throw new Error('Public key is missing');
				}
				const { payload, protectedHeader } = await jose.jwtVerify(token, pubKey);
				console.log('Token is valid. Payload:%s, Header: %s', payload, protectedHeader);
				if (!isTenantAllowed(payload)) {
					jwtAuthAuthorizationError(res, 'Tenant not allowed');
				}
				const isAdmin = payload['custom:is-super-admin'] as boolean;
				let adminRole = 'cms-default';
				if (isAdmin) {
					adminRole = 'admin';
				}
				const qpJwt: QpJwt = {
					gcip: {
						x_qp_entitlements: {
							workflow: payload['custom:x-qp-wf-id'] as string,
							api_roles: [payload['custom:x-qp-role-id'] as string, adminRole],
							service_id: payload['custom:x-qp-service-id'] as string,
						},
					},
				};
				req.jwt = qpJwt;
				next();
			} catch (e) {
				console.log('Token not valid!');
				console.log('Token %s error %s', token, e);
				jwtAuthAuthorizationError(res, 'Invalid token');
			}
		} else {
			jwt.verify(token, getKey, jwtVerifyOptions, (error: jwt.VerifyErrors, decoded: QpJwt) => {
				console.log('jwt %s', decoded);
				if (error) {
					console.log('error %s', error);
					jwtAuthAuthorizationError(res, 'Invalid token');
				} else if (!isTenantAllowed(decoded)) {
					jwtAuthAuthorizationError(res, 'Tenant not allowed');
				} else {
					req.jwt = decoded;
					next();
				}
			});
		}
	});
};
