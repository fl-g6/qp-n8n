import type { Response } from 'express';
import { Container } from 'typedi';

import type { User } from '@/databases/entities/user';
import { UserRepository } from '@/databases/repositories/user.repository';
import { AuthError } from '@/errors/response-errors/auth.error';
import { JwtService } from '@/services/jwt.service';

import { AuthService } from './auth.service';

interface AuthJwtPayload {
	/** User Id */
	id?: string;
	/** This hash is derived from email and bcrypt of password */
	hash?: string;
	/** This is a client generated unique string to prevent session hijacking */
	browserId?: string;
	email?: string;
}
interface IssuedJWT extends AuthJwtPayload {
	exp?: number;
}

// This method is still used by cloud hooks.
// DO NOT DELETE until the hooks have been updated
/** @deprecated Use `AuthService` instead */
export async function issueCookie(res: Response, user: User) {
	return Container.get(AuthService).issueCookie(res, user);
}

export async function resolveJwt(token: string): Promise<User> {
	const jwtPayload: IssuedJWT = await Container.get(JwtService).verify(token, {});

	// TODO: Use an in-memory ttl-cache to cache the User object for upto a minute
	const user = await Container.get(UserRepository).findOne({
		where: { id: jwtPayload.id },
	});

	// let passwordHash = null;
	// if (user?.password) {
	// 	passwordHash = hash(user.password);
	// }

	// // currently only LDAP users during synchronization
	// // can be set to disabled
	// if (user?.disabled) {
	// 	throw new AuthError('Unauthorized');
	// }

	// if (!user || jwtPayload.password !== passwordHash || user.email !== jwtPayload.email) {
	// 	// When owner hasn't been set up, the default user
	// 	// won't have email nor password (both equals null)
	// 	throw new ApplicationError('Invalid token content');
	// }

	// const jwtHashComputed = Container.get(AuthService).createJWTHash(user);

	//// or, If the user has been deactivated (i.e. LDAP users)
	//user.disabled ||
	if (
		// If not user is found
		!user ||
		// or, If the email or password has been updated
		jwtPayload.email !== user.email
	) {
		throw new AuthError('Unauthorized');
	}

	// // Check if the token was issued for another browser session, ignoring the endpoints that can't send custom headers
	// const endpoint = req.route ? `${req.baseUrl}${req.route.path}` : req.baseUrl;
	// if (req.method === 'GET' && skipBrowserIdCheckEndpoints.includes(endpoint)) {
	// 	this.logger.debug(`Skipped browserId check on ${endpoint}`);
	// } else if (
	// 	jwtPayload.browserId &&
	// 	(!req.browserId || jwtPayload.browserId !== this.hash(req.browserId))
	// ) {
	// 	this.logger.warn(`browserId check failed on ${endpoint}`);
	// 	throw new AuthError('Unauthorized');
	// }

	// if (jwtPayload.exp * 1000 - Date.now() < this.jwtRefreshTimeout) {
	// 	this.logger.debug('JWT about to expire. Will be refreshed');
	// 	this.issueCookie(res, user);
	// }

	return user;
}
