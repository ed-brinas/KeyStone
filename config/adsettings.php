<?php
return [
  'domain' => 'ncc.local',
  'searchBases' => ['OU=Users,OU=_Managed,DC=ncc,DC=local'],
  'ouStandard'  => 'OU=Users,OU=_Managed,DC=ncc,DC=local',
  'ouPrivilege' => 'OU=_AdminAccounts,DC=ncc,DC=local',
  'groups' => [
    'general' => ['CN=L2,OU=Groups,DC=ncc,DC=local'],
    'high'    => ['CN=L3,OU=Groups,DC=ncc,DC=local','CN=Domain Admins,CN=Users,DC=ncc,DC=local'],
  ],
  'standardGroups'   => ['CN=L1,OU=Groups,DC=ncc,DC=local','CN=L2,OU=Groups,DC=ncc,DC=local','CN=EMS-RDP,OU=Groups,DC=ncc,DC=local','CN=FEP-RDP,OU=Groups,DC=ncc,DC=local'],
  'privilegedGroups' => ['CN=L3,OU=Groups,DC=ncc,DC=local','CN=Domain Admins,CN=Users,DC=ncc,DC=local'],
  'privAdminSuffix'  => '-a',
  'privValidDays'    => 30,
];
