<?php

// Dynamically build connections for each domain in the .env file
$domains = array_filter(array_map('trim', explode(',', env('LDAP_DOMAINS', ''))));

$connections = [];

// Get settings from .env
$useSsl = env('LDAP_SSL', false);
$useTls = env('LDAP_TLS', false);
$port = env('LDAP_PORT', 389);
$insecure = env('LDAP_TLS_INSECURE', false);

// Last-ditch effort: If TLS is on, force-disable cert validation
// This is the only way to bypass self-signed cert errors if .env fails
$options = [];
if ($useTls && $insecure) {
    $options[LDAP_OPT_X_TLS_REQUIRE_CERT] = LDAP_OPT_X_TLS_NEVER;
}

foreach ($domains as $domain) {
    $connections[$domain] = [
        // --- FIX ---
        // Use the specific host from .env (e.g., dc01.ncc.lab)
        // This is more reliable if DNS auto-discovery is failing.
        'hosts' => [env('LDAP_HOST', $domain)], 
        
        'username' => env('LDAP_USERNAME'),
        'password' => env('LDAP_PASSWORD'),
        'port' => (int)$port,
        'base_dn' => 'dc=' . str_replace('.', ',dc=', $domain),
        'timeout' => env('LDAP_TIMEOUT', 5),
        'use_ssl' => $useSsl,
        'use_tls' => $useTls,
        'use_sasl' => env('LDAP_SASL', false),
        'sasl_options' => [],
        
        // Apply the TLS options
        'options' => $options, 
    ];
}

$defaultConnection = env('LDAP_CONNECTION', 'default');
if (!in_array($defaultConnection, $domains) && !empty($domains)) {
    $defaultConnection = $domains[0];
}

return [
    'default' => $defaultConnection,
    'connections' => $connections,
    'logging' => [
        'enabled' => env('LDAP_LOGGING', true),
        'channel' => env('LOG_CHANNEL', 'stack'),
        'level' => env('LOG_LEVEL', 'info'),
    ],
    'cache' => [
        'enabled' => env('LDAP_CACHE', false),
        'driver' => env('CACHE_DRIVER', 'file'),
    ],
];

