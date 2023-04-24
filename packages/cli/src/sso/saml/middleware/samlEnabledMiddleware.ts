import type { RequestHandler } from 'express';
<<<<<<< HEAD
import { isSamlLicensed, isSamlLicensedAndEnabled } from '../samlHelpers';

=======
import type { AuthenticatedRequest } from '../../../requests';
import { isSamlLicensed, isSamlLicensedAndEnabled } from '../samlHelpers';

export const samlLicensedOwnerMiddleware: RequestHandler = (
	req: AuthenticatedRequest,
	res,
	next,
) => {
	if (isSamlLicensed() && req.user?.globalRole.name === 'owner') {
		next();
	} else {
		res.status(401).json({ status: 'error', message: 'Unauthorized' });
	}
};

>>>>>>> master
export const samlLicensedAndEnabledMiddleware: RequestHandler = (req, res, next) => {
	if (isSamlLicensedAndEnabled()) {
		next();
	} else {
<<<<<<< HEAD
		res.status(403).json({ status: 'error', message: 'Unauthorized' });
=======
		res.status(401).json({ status: 'error', message: 'Unauthorized' });
>>>>>>> master
	}
};

export const samlLicensedMiddleware: RequestHandler = (req, res, next) => {
	if (isSamlLicensed()) {
		next();
	} else {
<<<<<<< HEAD
		res.status(403).json({ status: 'error', message: 'Unauthorized' });
=======
		res.status(401).json({ status: 'error', message: 'Unauthorized' });
>>>>>>> master
	}
};
