<?php

/**
 * --------------------------------------------------------------------------
 * KeyStone Application Settings (APPSETTINGS)
 * --------------------------------------------------------------------------
 *
 * This file mirrors the 'APPSETTINGS' section from the project requirements
 * document. It centralizes all custom configuration for the KeyStone
 * Active Directory management portal, using camelCase for keys.
 *
 */
return [

    'adSettings' => [
        'forestRootDomain' => env('LDAP_FOREST_ROOT_DOMAIN', 'ncc.local'),
        'domains' => explode(',', env('LDAP_DOMAINS', 'ncc.local,ems.ncc.local')),
    ],

    'applicationAccessControl' => [
        /**
         * AD security groups whose members are allowed general access
         * to the admin portal.
         */
        'generalAccessGroups' => ['CN=L2,CN=Users,{domain-components}',],

        /**
         * AD security groups whose members are considered high-privilege.
         * These users may have access to create admin accounts or view logs.
         */
        'highPrivilegeGroups' => [
            'CN=L3,CN=Users,{domain-components}',
            'CN=Domain Admins,CN=Users,{domain-components}'
        ],
    ],

    'provisioning' => [
        /**
         * The OUs to search for users within. The {domain-components}
         * placeholder will be automatically replaced with the correct DC
         * format for the selected domain (e.g., 'dc=ncc,dc=local').
         */
        'searchBaseOus' => [
            'OU=Users,OU=_Managed,{domain-components}',
        ],

        /**
         * The default OU where new standard user accounts will be created.
         */
        'ouStandardUser' => 'OU=Users,OU=_Managed,{domain-components}',

        /**
         * The OU where new privileged user accounts (e.g., '-a' accounts)
         * will be created.
         */
        'ouPrivilegeUser' => 'OU=_AdminAccounts,{domain-components}',

        /**
         * A list of optional AD security groups that can be assigned to a
         * new standard user during creation.
         */
        'optionalGroupsForStandardUser' => [
            'CN=L1,CN=Users,{domain-components}',
            'CN=L2,CN=Users,{domain-components}',
            'CN=EMS-RDP,CN=Users,{domain-components}',
            'CN=FEP-RDP,CN=Users,{domain-components}'
        ],

        /**
         * A list of optional AD security groups that can be assigned to a
         * new privileged user during creation.
         */
        'optionalGroupsForHighPrivilegeUsers' => [
            'CN=L3,CN=Users,{domain-components}',
            'CN=Domain Admins,CN=Users,{domain-components}'
        ],
    ],
];
