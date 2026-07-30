INSERT INTO
  roles (name, description, permissions)
VALUES
  (
    'owner',
    'Full access to all workspace resources and settings',
    '{workspace.edit,workspace.delete,members.view,members.edit,settings.view,settings.edit,domains.view,domains.edit,sso.view,sso.edit,cas.view,cas.edit,targets.view,targets.edit,principals.view,principals.edit,daemons.view,daemons.edit,teams.view,teams.edit,service_accounts.view,service_accounts.edit}'
  ),
  (
    'member',
    'View workspace resources',
    '{members.view,settings.view,domains.view,sso.view,cas.view,targets.view,principals.view,daemons.view,teams.view,service_accounts.view}'
  ),
  (
    'admin',
    'Manage resources like targets, daemons, teams, and service accounts',
    '{members.view,settings.view,domains.view,sso.view,cas.view,targets.view,targets.edit,principals.view,principals.edit,daemons.view,daemons.edit,teams.view,teams.edit,service_accounts.view,service_accounts.edit}'
  )
ON CONFLICT (name) DO NOTHING;
