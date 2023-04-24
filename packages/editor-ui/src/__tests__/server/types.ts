<<<<<<< HEAD
import type { Registry } from 'miragejs';

// eslint-disable-next-line import/no-unresolved
import type Schema from 'miragejs/orm/schema';

import type { models } from './models';
import type { factories } from './factories';
=======
import { Registry } from 'miragejs';

// eslint-disable-next-line import/no-unresolved
import Schema from 'miragejs/orm/schema';

import { models } from './models';
import { factories } from './factories';
>>>>>>> master

type AppRegistry = Registry<typeof models, typeof factories>;
export type AppSchema = Schema<AppRegistry>;
