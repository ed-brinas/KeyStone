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
        'forestRootDomain' => env('AD_FOREST_ROOT_DOMAIN', 'ncc.local'),
        'domains' => explode(',', env('AD_DOMAINS', 'ncc.local')),
    ],

    'applicationAccessControl' => [
        /**
         * AD security groups whose members are allowed general access
         * to the admin portal.
         */
        'generalAccessGroups' => ['L2'],

        /**
         * AD security groups whose members are considered high-privilege.
         * These users may have access to create admin accounts or view logs.
         */
        'highPrivilegeGroups' => ['L3', 'Domain Admins'],
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
            'L1',
            'L2',
            'EMS-RDP',
            'FEP-RDP',
        ],

        /**
         * A list of optional AD security groups that can be assigned to a
         * new privileged user during creation.
         */
        'optionalGroupsForHighPrivilegeUsers' => [
            'L3',
            'Domain Admins',
        ],
    ],
];
