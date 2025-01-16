# n8n Fork for Quickplay Videocoud Platform

- [Compare this fork with original n8n repo](https://github.com/n8n-io/n8n/compare/master...fl-g6:qp-n8n:master) to know what exactly was changed in this fork

## Development setup

```
pnpm install
pnpm run build
pnpm run dev || pnpm start

Clean, Install, Build & Run

rm -rf node_modules pnpm-lock.yaml dist build out && pnpm store prune && pnpm install && pnpm run build && pnpm start
```

## Hiding UI components

To hide or change the visibility conditions of the sidebar elements, start your research with a file `packages/editor-ui/src/components/MainSidebar.vue`.
You can use `v-if` attribute to control visibility of elements and use any property from `computed` object as value. In `computed` you can refer to different stores (packages/editor-ui/src/stores).

To control access to routes, refer to `packages/editor-ui/src/router.ts`.

Some expressions use `frontendSettings` (search for `this.frontendSettings =` in `packages/cli/src/Server.ts`). Many of these params obtain its value from configuration - `packages/cli/src/config/schema.ts`.


## Update from upstream

The procedure of actions:
- update from upstream (see commands below)
- commit merge result with all conflicts
- resolve conflicts

To update from upstream tag:
```bash
git fetch upstream --tags
git checkout master
git pull
git checkout upgrade/n8n-v1.74.1
git merge tags/n8n@1.74.1
```

Resolving merge conflicts:
- To find all merge conflicts, search for ">>>>>>> n8n@1.74.1" in all files.
- Open changes: https://github.com/n8n-io/n8n/compare/master...fl-g6:qp-n8n:master
- For each conflict file do:
  - Open file
  - Look for original [changes](https://github.com/n8n-io/n8n/compare/master...fl-g6:qp-n8n:master) in file **to understand what was implemented and why**.
  - In general case, we have to accept **incomming changes** and apply qickplay changes according to new architecture/changes.

- Refer the breaking changes across (Eg: 'typedi' with '@n8n/di')

git merge tags/n8n@1.74.1
Auto-merging CHANGELOG.md
CONFLICT (content): Merge conflict in CHANGELOG.md
Auto-merging cypress/constants.ts
CONFLICT (content): Merge conflict in cypress/constants.ts
Auto-merging cypress/e2e/19-execution.cy.ts
CONFLICT (content): Merge conflict in cypress/e2e/19-execution.cy.ts
CONFLICT (modify/delete): cypress/e2e/36-suggested-templates.cy.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of cypress/e2e/36-suggested-templates.cy.ts left in tree.
Auto-merging cypress/e2e/4-node-creator.cy.ts
CONFLICT (content): Merge conflict in cypress/e2e/4-node-creator.cy.ts
Auto-merging cypress/e2e/5-ndv.cy.ts
CONFLICT (content): Merge conflict in cypress/e2e/5-ndv.cy.ts
Auto-merging cypress/fixtures/Floating_Nodes.json
CONFLICT (content): Merge conflict in cypress/fixtures/Floating_Nodes.json
Auto-merging cypress/fixtures/Lots_of_nodes.json
CONFLICT (content): Merge conflict in cypress/fixtures/Lots_of_nodes.json
Auto-merging cypress/fixtures/Node_IO_filter.json
CONFLICT (content): Merge conflict in cypress/fixtures/Node_IO_filter.json
CONFLICT (modify/delete): cypress/fixtures/Suggested_Templates.json deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of cypress/fixtures/Suggested_Templates.json left in tree.
Auto-merging cypress/fixtures/Test_workflow_5.json
CONFLICT (content): Merge conflict in cypress/fixtures/Test_workflow_5.json
Auto-merging cypress/fixtures/Test_workflow_filter.json
CONFLICT (content): Merge conflict in cypress/fixtures/Test_workflow_filter.json
Auto-merging cypress/fixtures/Test_workflow_ndv_version.json
CONFLICT (content): Merge conflict in cypress/fixtures/Test_workflow_ndv_version.json
Auto-merging cypress/fixtures/Test_workflow_schema_test.json
CONFLICT (content): Merge conflict in cypress/fixtures/Test_workflow_schema_test.json
Auto-merging cypress/fixtures/Test_workflow_schema_test_pinned_data.json
CONFLICT (content): Merge conflict in cypress/fixtures/Test_workflow_schema_test_pinned_data.json
Auto-merging cypress/fixtures/Test_workflow_webhook_with_pin_data.json
CONFLICT (content): Merge conflict in cypress/fixtures/Test_workflow_webhook_with_pin_data.json
Auto-merging cypress/fixtures/Test_workflow_xml_output.json
CONFLICT (content): Merge conflict in cypress/fixtures/Test_workflow_xml_output.json
Auto-merging cypress/fixtures/expression_with_paired_item_in_multi_input_node.json
CONFLICT (content): Merge conflict in cypress/fixtures/expression_with_paired_item_in_multi_input_node.json
Auto-merging cypress/fixtures/workflow-with-unknown-credentials.json
CONFLICT (content): Merge conflict in cypress/fixtures/workflow-with-unknown-credentials.json
Auto-merging cypress/fixtures/workflow-with-unknown-nodes.json
CONFLICT (content): Merge conflict in cypress/fixtures/workflow-with-unknown-nodes.json
Auto-merging package.json
CONFLICT (content): Merge conflict in package.json
Auto-merging packages/@n8n/nodes-langchain/package.json
CONFLICT (content): Merge conflict in packages/@n8n/nodes-langchain/package.json
Auto-merging packages/cli/package.json
CONFLICT (content): Merge conflict in packages/cli/package.json
CONFLICT (modify/delete): packages/cli/src/ExternalSecrets/constants.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/cli/src/ExternalSecrets/constants.ts left in tree.
CONFLICT (modify/delete): packages/cli/src/GenericHelpers.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/cli/src/GenericHelpers.ts left in tree.
CONFLICT (modify/delete): packages/cli/src/Interfaces.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/cli/src/Interfaces.ts left in tree.
CONFLICT (modify/delete): packages/cli/src/Server.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/cli/src/Server.ts left in tree.
CONFLICT (modify/delete): packages/cli/src/UserManagement/UserManagementHelper.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/cli/src/UserManagement/UserManagementHelper.ts left in tree.
CONFLICT (file location): packages/cli/test/unit/workflow-execution.service.test.ts added in HEAD inside a directory that was renamed in tags/n8n@1.74.1, suggesting it should perhaps be moved to packages/cli/src/__tests__/workflow-execution.service.test.ts.
Auto-merging packages/cli/src/config/schema.ts
CONFLICT (content): Merge conflict in packages/cli/src/config/schema.ts
Auto-merging packages/cli/src/controllers/users.controller.ts
CONFLICT (content): Merge conflict in packages/cli/src/controllers/users.controller.ts
Auto-merging packages/cli/src/databases/entities/user.ts
CONFLICT (modify/delete): packages/cli/src/databases/repositories/role.repository.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/cli/src/databases/repositories/role.repository.ts left in tree.
Auto-merging packages/cli/src/services/frontend.service.ts
CONFLICT (content): Merge conflict in packages/cli/src/services/frontend.service.ts
Auto-merging packages/cli/src/webhooks/webhook-helpers.ts
CONFLICT (content): Merge conflict in packages/cli/src/webhooks/webhook-helpers.ts
CONFLICT (modify/delete): packages/cli/src/workflows/workflowExecution.service.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/cli/src/workflows/workflowExecution.service.ts left in tree.
Auto-merging packages/cli/templates/form-trigger-404.handlebars
CONFLICT (directory rename split): Unclear where to rename packages/cli/test/unit/controllers to; it was renamed to multiple other directories, with no destination getting a majority of the files.
Auto-merging packages/core/package.json
CONFLICT (content): Merge conflict in packages/core/package.json
Auto-merging packages/core/src/WorkflowExecute.ts
CONFLICT (content): Merge conflict in packages/core/src/WorkflowExecute.ts
Auto-merging packages/design-system/package.json
CONFLICT (content): Merge conflict in packages/design-system/package.json
Auto-merging packages/design-system/src/components/N8nMenu/Menu.stories.ts
Auto-merging packages/design-system/src/components/N8nMenu/Menu.vue
CONFLICT (content): Merge conflict in packages/design-system/src/components/N8nMenu/Menu.vue
Auto-merging packages/design-system/src/components/N8nMenuItem/MenuItem.stories.ts
Auto-merging packages/design-system/src/components/N8nMenuItem/MenuItem.vue
CONFLICT (content): Merge conflict in packages/design-system/src/components/N8nMenuItem/MenuItem.vue
Auto-merging packages/design-system/src/components/N8nMenuItem/routerUtil.ts
CONFLICT (add/add): Merge conflict in packages/design-system/src/components/N8nMenuItem/routerUtil.ts
Auto-merging packages/design-system/src/components/N8nRadioButtons/RadioButtons.vue
CONFLICT (content): Merge conflict in packages/design-system/src/components/N8nRadioButtons/RadioButtons.vue
Auto-merging packages/design-system/src/components/N8nTooltip/Tooltip.vue
CONFLICT (content): Merge conflict in packages/design-system/src/components/N8nTooltip/Tooltip.vue
Auto-merging packages/design-system/src/types/menu.ts
CONFLICT (content): Merge conflict in packages/design-system/src/types/menu.ts
Auto-merging packages/editor-ui/package.json
CONFLICT (content): Merge conflict in packages/editor-ui/package.json
Auto-merging packages/editor-ui/src/Interface.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/Interface.ts
Auto-merging packages/editor-ui/src/components/CommunityPackageCard.vue
CONFLICT (modify/delete): packages/editor-ui/src/components/ExecutionsView/ExecutionCard.vue deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/editor-ui/src/components/ExecutionsView/ExecutionCard.vue left in tree.
Auto-merging packages/editor-ui/src/components/MainHeader/MainHeader.vue
CONFLICT (content): Merge conflict in packages/editor-ui/src/components/MainHeader/MainHeader.vue
Auto-merging packages/editor-ui/src/components/MainSidebar.vue
CONFLICT (content): Merge conflict in packages/editor-ui/src/components/MainSidebar.vue
Auto-merging packages/editor-ui/src/components/SettingsSidebar.vue
CONFLICT (content): Merge conflict in packages/editor-ui/src/components/SettingsSidebar.vue
Auto-merging packages/editor-ui/src/components/Sticky.vue
CONFLICT (content): Merge conflict in packages/editor-ui/src/components/Sticky.vue
CONFLICT (modify/delete): packages/editor-ui/src/components/__tests__/RBAC.test.ts deleted in tags/n8n@1.74.1 and modified in HEAD.  Version HEAD of packages/editor-ui/src/components/__tests__/RBAC.test.ts left in tree.
Auto-merging packages/editor-ui/src/components/executions/global/GlobalExecutionsList.test.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/components/executions/global/GlobalExecutionsList.test.ts
Auto-merging packages/editor-ui/src/composables/useHistoryHelper.test.ts
Auto-merging packages/editor-ui/src/composables/useNodeHelpers.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/composables/useNodeHelpers.ts
Auto-merging packages/editor-ui/src/plugins/i18n/locales/en.json
CONFLICT (content): Merge conflict in packages/editor-ui/src/plugins/i18n/locales/en.json
Auto-merging packages/editor-ui/src/router.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/router.ts
Auto-merging packages/editor-ui/src/stores/ui.store.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/stores/ui.store.ts
Auto-merging packages/editor-ui/src/utils/nodeViewUtils.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/utils/nodeViewUtils.ts
Auto-merging packages/editor-ui/src/views/NodeView.vue
CONFLICT (content): Merge conflict in packages/editor-ui/src/views/NodeView.vue
Auto-merging packages/editor-ui/src/views/SamlOnboarding.test.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/views/SamlOnboarding.test.ts
Auto-merging packages/editor-ui/src/views/WorkflowHistory.test.ts
Auto-merging packages/node-dev/package.json
CONFLICT (content): Merge conflict in packages/node-dev/package.json
Auto-merging packages/nodes-base/nodes/Airtable/v1/AirtableV1.node.ts
Auto-merging packages/nodes-base/nodes/Airtable/v1/GenericFunctions.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/Airtable/v1/GenericFunctions.ts
Auto-merging packages/nodes-base/nodes/Airtable/v2/actions/record/search.operation.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/Airtable/v2/actions/record/search.operation.ts
Auto-merging packages/nodes-base/nodes/Airtable/v2/transport/index.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/Airtable/v2/transport/index.ts
Auto-merging packages/nodes-base/nodes/Amqp/AmqpTrigger.node.ts
Auto-merging packages/nodes-base/nodes/Asana/Asana.node.ts
Auto-merging packages/nodes-base/nodes/Asana/AsanaTrigger.node.ts
Auto-merging packages/nodes-base/nodes/Asana/GenericFunctions.ts
Auto-merging packages/nodes-base/nodes/Aws/SQS/AwsSqs.node.ts
Auto-merging packages/nodes-base/nodes/Discord/v2/actions/webhook/sendLegacy.operation.ts
Auto-merging packages/nodes-base/nodes/Form/common.descriptions.ts
Auto-merging packages/nodes-base/nodes/ManualTrigger/ManualTrigger.node.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/ManualTrigger/ManualTrigger.node.ts
Auto-merging packages/nodes-base/nodes/Merge/v1/MergeV1.node.ts
Auto-merging packages/nodes-base/nodes/Merge/v2/MergeV2.node.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/Merge/v2/MergeV2.node.ts
Auto-merging packages/nodes-base/nodes/Microsoft/Sql/GenericFunctions.ts
Auto-merging packages/nodes-base/nodes/Microsoft/Sql/test/utils.test.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/Microsoft/Sql/test/utils.test.ts
Auto-merging packages/nodes-base/nodes/NocoDB/GenericFunctions.ts
Auto-merging packages/nodes-base/nodes/NocoDB/NocoDB.node.ts
Auto-merging packages/nodes-base/nodes/Notion/shared/GenericFunctions.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/Notion/shared/GenericFunctions.ts
Auto-merging packages/nodes-base/nodes/Notion/v2/NotionV2.node.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/Notion/v2/NotionV2.node.ts
Auto-merging packages/nodes-base/nodes/Redis/Redis.node.ts
CONFLICT (content): Merge conflict in packages/nodes-base/nodes/Redis/Redis.node.ts
Auto-merging packages/nodes-base/nodes/Set/v1/SetV1.node.ts
Auto-merging packages/nodes-base/nodes/Switch/V3/SwitchV3.node.ts
Auto-merging packages/nodes-base/nodes/TheHiveProject/descriptions/filter.description.ts
Auto-merging packages/nodes-base/package.json
CONFLICT (content): Merge conflict in packages/nodes-base/package.json
Auto-merging packages/workflow/package.json
CONFLICT (content): Merge conflict in packages/workflow/package.json
Auto-merging packages/workflow/src/Extensions/DateExtensions.ts
CONFLICT (content): Merge conflict in packages/workflow/src/Extensions/DateExtensions.ts
Auto-merging packages/workflow/test/TelemetryHelpers.test.ts
CONFLICT (content): Merge conflict in packages/workflow/test/TelemetryHelpers.test.ts
Auto-merging pnpm-lock.yaml
CONFLICT (content): Merge conflict in pnpm-lock.yaml
Automatic merge failed; fix conflicts and then commit the result.

To update from upstream tag:
```bash
git fetch upstream --tags
git checkout master
git pull
git checkout $new_branch
git merge n8n@1.25.1
```

Resolving merge conflicts:
- To find all merge conflicts, search for ">>>>>>> n8n@1.25.1" in all files.
- Open changes: https://github.com/n8n-io/n8n/compare/master...fl-g6:qp-n8n:master
- For each conflict file do:
  - Open file
  - Look for original [changes](https://github.com/n8n-io/n8n/compare/master...fl-g6:qp-n8n:master) in file **to understand what was implemented and why**.
  - In general case, we have to accept **incomming changes** and apply qickplay changes according to new architecture/changes.


### `git merge n8n@1.25.1` Log

```bash
$ git merge n8n@1.25.1
Auto-merging packages/cli/src/Server.ts
CONFLICT (content): Merge conflict in packages/cli/src/Server.ts
CONFLICT (modify/delete): packages/cli/src/middlewares/externalJWTAuth.ts deleted in n8n@1.25.1 and modified in HEAD.  Version HEAD of packages/cli/src/middlewares/externalJWTAuth.ts left in tree.
Auto-merging packages/design-system/src/css/skeleton.scss
CONFLICT (content): Merge conflict in packages/design-system/src/css/skeleton.scss
Auto-merging packages/editor-ui/src/components/ExecutionsView/ExecutionCard.vue
Auto-merging packages/editor-ui/src/components/MainSidebar.vue
CONFLICT (content): Merge conflict in packages/editor-ui/src/components/MainSidebar.vue
Auto-merging packages/editor-ui/src/router.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/router.ts
Auto-merging packages/editor-ui/src/utils/nodeViewUtils.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/utils/nodeViewUtils.ts
Auto-merging packages/editor-ui/src/utils/userUtils.ts
CONFLICT (content): Merge conflict in packages/editor-ui/src/utils/userUtils.ts
Automatic merge failed; fix conflicts and then commit the result.
```

Key commits:
- Nov 23, 2023 [feat(editor): Add routing middleware, permission checks, RBAC store, RBAC component](https://github.com/n8n-io/n8n/commit/67a88914f2f2d11c413e7f627d659333d8419af8)
- Dec 27, 2023 [refactor(core): Use Dependency Injection for all Controller classes (no-changelog)](https://github.com/n8n-io/n8n/commit/f69ddcd79646389f2fdbc764b96a7e42e4aa263b)
