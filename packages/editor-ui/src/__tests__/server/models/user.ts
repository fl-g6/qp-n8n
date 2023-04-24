<<<<<<< HEAD
import type { IUser } from '@/Interface';
=======
import { IUser } from '@/Interface';
>>>>>>> master
import { Model } from 'miragejs';
import type { ModelDefinition } from 'miragejs/-types';

export const UserModel: ModelDefinition<IUser> = Model.extend({});
