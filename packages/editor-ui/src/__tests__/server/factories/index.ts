import { userFactory } from './user';
import { credentialFactory } from './credential';
import { credentialTypeFactory } from './credentialType';
<<<<<<< HEAD
import { variableFactory } from './variable';
=======
>>>>>>> master

export * from './user';
export * from './credential';
export * from './credentialType';
<<<<<<< HEAD
export * from './variable';
=======
>>>>>>> master

export const factories = {
	credential: credentialFactory,
	credentialType: credentialTypeFactory,
	user: userFactory,
<<<<<<< HEAD
	variable: variableFactory,
=======
>>>>>>> master
};
