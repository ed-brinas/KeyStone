<?php

// Note: The 'use LdapRecord\Connection;' statement has been removed as it's no longer needed after the fix.

// Dynamically build connections from keystone config
$connections = [];
$keystoneConfig = require __DIR__ . '/keystone.php';
$domains = $keystoneConfig['adSettings']['domains'] ?? [env('LDAP_HOST')];
$defaultBaseDn = env('LDAP_BASE_DN', '');

foreach ($domains as $domain) {
    // Generate a connection name, e.g., 'ncc_local' from 'ncc.local'
    $connectionName = str_replace('.', '_', $domain);
    
    // Convert domain to DN format, e.g., 'dc=ncc,dc=local'
    $baseDn = 'dc=' . str_replace('.', ',dc=', $domain);

    $connections[$connectionName] = [
        'hosts' => [$domain], // Use the domain itself as the host
        'base_dn' => $baseDn,
        'username' => env('LDAP_USERNAME'),
        'password' => env('LDAP_PASSWORD'),
        'port' => env('LDAP_PORT', 389),
        'use_ssl' => env('LDAP_SSL', false),
        'use_tls' => env('LDAP_TLS', false),
        'options' => [
            // See: http://php.net/ldap_set_option
            // FIX: Use the correct global PHP constants for LDAP options.
            LDAP_OPT_PROTOCOL_VERSION => 3,
            LDAP_OPT_REFERRALS => false,
        ],
        'version' => 3,
        'timeout' => env('LDAP_TIMEOUT', 5),
        'follow_referrals' => false,
    ];
}


return [
    /*
    |--------------------------------------------------------------------------
    | Default LDAP Connection Name
    |--------------------------------------------------------------------------
    */
    'default' => env('LDAP_CONNECTION', 'default'),

    /*
    |--------------------------------------------------------------------------
    | LDAP Connections
    |--------------------------------------------------------------------------
    */
    'connections' => $connections,

    /*
    |--------------------------------------------------------------------------
    | LDAP Logging
    |--------------------------------------------------------------------------
    */
    'logging' => [
        'enabled' => env('LDAP_LOGGING', true),
        'channel' => env('LOG_CHANNEL', 'stack'),
    ],

    /*
    |--------------------------------------------------------------------------
    | LDAP Cache
    |--------------------------------------------------------------------------
    */
    'cache' => [
        'enabled' => env('LDAP_CACHE', false),
        'driver' => env('CACHE_DRIVER', 'file'),
    ],
];

