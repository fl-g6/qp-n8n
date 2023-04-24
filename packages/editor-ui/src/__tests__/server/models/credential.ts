<<<<<<< HEAD
import type { ICredentialsResponse } from '@/Interface';
=======
import { ICredentialsResponse } from '@/Interface';
>>>>>>> master
import { Model } from 'miragejs';
import type { ModelDefinition } from 'miragejs/-types';

export const CredentialModel: ModelDefinition<ICredentialsResponse> = Model.extend({});
