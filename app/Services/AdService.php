<?php

namespace App\Services;

use Carbon\Carbon;
use LdapRecord\Container;
use LdapRecord\LdapRecordException;
use LdapRecord\Connection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use LdapRecord\Models\ActiveDirectory\User as LdapUser;
use LdapRecord\Models\ActiveDirectory\Group as LdapGroup;
use LdapRecord\Models\Attributes\Sid as LdapSid;
use LdapRecord\Models\ModelNotFoundException;
use Illuminate\Support\Str;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;

class AdService
{
    // ===================================================================
    // PROTECTED METHODS
    // ===================================================================

    /**
     * Get the base DN for a specific domain from keystone config.
     * This function converts a domain string (e.g., "ncc.local")
     * into its DN component format (e.g., "dc=ncc,dc=local").
     *
     * @param string $domain
     * @return string
     */
    protected function getBaseDn(string $domain): string
    {
        return 'dc=' . str_replace('.', ',dc=', $domain);
    }

    /**
     * Get a domain-specific, model-based query builder.
     *
     * @param string $domain
     * @return \LdapRecord\Query\Model\Builder
     */
    protected function newQuery(string $domain): \LdapRecord\Query\Model\Builder
    {
        return LdapUser::on($domain);
    }

    /**
     * Encodes a password for Active Directory (unicodePwd).
     *
     * @param string $password
     * @return string
     */
    protected function encodePassword(string $password): string
    {
        return iconv("UTF-8", "UTF-16LE", '"' . $password . '"');
    }

    /**
     * Build the Distinguished Name for a new user object.
     *
     * @param string $cn
     * @param string $domain
     * @param bool $isPrivileged
     * @return string
     */
    protected function buildDn(string $cn, string $domain, bool $isPrivileged = false): string
    {
        $ouConfigPath = $isPrivileged
            ? 'keystone.provisioning.ouPrivilegeUser'
            : 'keystone.provisioning.ouStandardUser';

        $ouTemplate = config($ouConfigPath, 'OU=Users,OU=_Managed,{domain-components}');

        // Use the new helper function to resolve the domain components
        $ou = $this->resolveDnTemplate($ouTemplate, $domain);

        return "CN=$cn,$ou";
    }

    /**
     * Add a user to a specified Active Directory group.
     *
     * @param string $domain
     * @param LdapUser $user
     * @param string $groupName (This must be the full DN of the group)
     * @return bool
     */
    protected function addUserToGroup(string $domain, LdapUser $user, string $groupName): bool
    {
        try {
            Log::info("Attempting to add '{$user->getName()}' to group '{$groupName}'...");

            $group = LdapGroup::on($domain)
                ->where('distinguishedname', '=', $groupName)
                ->first();

            if ($group) {
                // Check if user is already a member to avoid unnecessary operations
                if (!$user->groups()->exists($group)) {
                    $group->members()->attach($user);
                    Log::info("Added '{$user->getName()}' to group '{$groupName}'.");
                } else {
                    Log::info("'{$user->getName()}' is already a member of group '{$groupName}'.");
                }
                return true;
            }

            Log::warning("Group '{$groupName}' not found in domain '{$domain}'.");

        } catch (\Exception $e) {
            Log::error("Failed to add '{$user->getName()}' to group '{$groupName}': " . $e->getMessage());
        }

        return false;
    }

    /**
     * Resolves a DN template string by replacing {domain-components} with the correct DN.
     *
     * @param string $dnTemplate The DN template string (e.g., "CN=Users,{domain-components}")
     * @param string $domain The domain string (e.g., "ncc.local")
     * @return string The resolved DN string
     */
    protected function resolveDnTemplate(string $dnTemplate, string $domain): string
    {
        // Use the existing helper function to resolve the domain components
        $domainDn = $this->getBaseDn($domain);

        // Replace the placeholder
        return str_replace('{domain-components}', $domainDn, $dnTemplate);
    }

    /**
     * Generate a secure, random password.
     * Logic ported from AdService.cs GeneratePassword()
     *
     * @return string
     */
    protected function generatePassword(): string
    {
        $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lower = 'abcdefghijkmnpqrstuvwxyz';
        $number = '123456789';
        $special = '!@#$';

        $allChars = $upper . $lower . $number . $special;

        $password = '';
        $password .= $upper[random_int(0, strlen($upper) - 1)];
        $password .= $lower[random_int(0, strlen($lower) - 1)];
        $password .= $number[random_int(0, strlen($number) - 1)];
        $password .= $special[random_int(0, strlen($special) - 1)];

        for ($i = 0; $i < 12; $i++) {
            $password .= $allChars[random_int(0, strlen($allChars) - 1)];
        }

        return str_shuffle($password);
    }

    /**
     * Provisions a new AD user (standard or admin).
     * (Assumes $data contains snake_case keys from validation)
     *
     * @param array $data
     * @param boolean $isAdmin
     * @return array ['user' => LdapUser, 'initialPassword' => string]
     */
    protected function provisionAdUser(array $data, bool $isAdmin = false): array
    {
        Log::debug('User provisioning data:', array_merge($data, ['isAdmin' => $isAdmin]));

        $domain     = $data['domain'];
        $firstName  = Str::title($data['first_name']);
        $lastName   = Str::title($data['last_name']);

        // --- Conditional Attributes ---
        if ($isAdmin) {
            $cn       = "admin-".strtolower($data['first_name'].$data['last_name']);
            $sam      = $data['badge_number'].'-a';
            $dn       = $this->buildDn($cn, $domain, true);
            $expires  = Carbon::now()->addMonth()->timestamp; // Admin accounts expire in 1 month
        } else {
            $cn       = $firstName." ".$lastName;
            $sam      = $data['badge_number'];
            $dn       = $this->buildDn($cn, $domain, false);
            $expires  = $this->convertDateToAdTimestamp($data['badge_expiration_date']);
        }

        Log::info("LDAP: DN set to: '{$dn}'");

        try {
            // 1. Build DN and create base user object
            $user                       = new LdapUser;
            $user->cn                   = $cn;
            $user->samaccountname       = $sam;
            $user->userprincipalname    = $sam.'@'.$domain;
            $user->displayname          = $cn;
            $user->givenname            = $firstName;
            $user->sn                   = $lastName;
            $user->useraccountcontrol   = 544; // Enabled, password change required
            $user->accountExpires       = $expires;

            // --- Standard-User-Only Attributes ---
            if (!$isAdmin) {
                $user->info                 = $data['date_of_birth'];
                $user->mail                 = $sam.'@'.$domain;
                $user->mobile               = $data['mobile_number'];
            }

            $user->setDn($dn);
            $user->save();

            Log::info("LDAP: Created minimal user object '{$cn}' successfully.");

            // Reload the user entry before resetting its password to ensure replication completion:
            sleep(1);
            $user->refresh();

            // 2. Generate password
            $initialPassword = $this->generatePassword();
            $this->resetPassword($user, $initialPassword, true);

            // 3. Add to groups
            if ($isAdmin) {
                // --- Admin Group Logic ---
                $arrPrivilegeGroups = $data['groups_privilege_user'] ?? null;
                if (is_array($arrPrivilegeGroups) && !empty($arrPrivilegeGroups)) {
                    foreach ($arrPrivilegeGroups as $privilegeGroup) {
                        $this->addUserToGroup($domain, $user, $privilegeGroup);
                    }
                }

                // Add to default privilege group from config
                try {
                    $groupTemplate = config('keystone.provisioning.ouPrivilegeUserGroup');
                    if ($groupTemplate) {
                        $defaultPrivilegeGroupDn = $this->resolveDnTemplate($groupTemplate, $domain);
                        Log::info("Adding admin user to default privilege group: {$defaultPrivilegeGroupDn}");
                        $this->addUserToGroup($domain, $user, $defaultPrivilegeGroupDn);
                    } else {
                        Log::warning("keystone.provisioning.ouPrivilegeUserGroup is not defined in config.");
                    }
                } catch (\Exception $e) {
                    Log::error("Failed to add admin user to default privilege group: " . $e->getMessage());
                }
            } else {
                // --- Standard Group Logic ---
                $arrStandardGroups = $data['groups_standard_user'] ?? null;
                if (is_array($arrStandardGroups) && !empty($arrStandardGroups)) {
                    foreach ($arrStandardGroups as $standardGroup) {
                        $this->addUserToGroup($domain, $user, $standardGroup);
                    }
                }
            }

            return [
                'user' => $user ?? null,
                'initialPassword' => $initialPassword ?? null, // Standardized key
            ];

        } catch (\Exception $e) {
            Log::error("User provisioning failed for '{$cn}': " . $e->getMessage());
            throw $e;
        }
    }

    // ===================================================================
    // PUBLIC METHODS
    // ===================================================================

    /**
     * Attempt to bind a user to a specific domain connection.
     *
     * @param string $domain
     * @param string $username
     * @param string $password
     * @return LdapUser|null
     */
    public function login(string $domain, string $username, string $password): ?LdapUser
    {
        try {
            // We must first find the user's full UPN to bind with.
            // Binding with sAMAccountName is unreliable.
            $user = $this->findUserBySamAccountName($username, $domain);

            if (!$user) {
                Log::warning("Login attempt: User '{$username}' not found on domain '{$domain}'.");
                return null;
            }

            $userPrincipalName = $user->getFirstAttribute('userprincipalname');
            if (empty($userPrincipalName)) {
                Log::error("Login attempt: User '{$username}' has no UserPrincipalName. Cannot bind.");
                return null;
            }

            // Get the connection from the container
            $connection = Container::getConnection($domain);

            // Attempt to bind as the user
            if ($connection->auth()->attempt($userPrincipalName, $password)) {
                return $user; // Return the user object on successful login
            }

            return null;

        } catch (\Exception $e) {
            Log::error("LDAP bind attempt failed for user {$username}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Find a user by their sAMAccountName on a specific domain.
     *
     * @param string $username
     * @param string $domain
     * @return \LdapRecord\Models\ActiveDirectory\User|null
     */
    public function findUserBySamAccountName(string $username, string $domain): ?LdapUser
    {
        Log::info("Attempting to find user by sAMAccountName: {$username}");
        try {
            $query = $this->newQuery($domain);
            $user = $query->where('samaccountname', '=', $username)->first();

            if (!$user) {
                Log::info("User '{$username}' not found.");
                return null;
            }

            Log::info("User '{$username}' found: ".$user->getDn());
            return $user;

        } catch (ModelNotFoundException $e) {
            Log::warning("User '{$username}' not found on domain '{$domain}'.");
            return null;
        } catch (\Exception $e) {
            Log::error("Error finding user '{$username}' on domain '{$domain}': " . $e->getMessage());
            return null;
        }
    }

    /**
     * Check if an admin account exists for a given base sAMAccountName.
     *
     * @param string $domain
     * @param string $baseSamAccountName
     * @return bool
     */
    public function checkIfAdminAccountExists(string $domain, string $baseSamAccountName): bool
    {
        $adminSam = "{$baseSamAccountName}-a";
        return $this->findUserBySamAccountName($adminSam, $domain) !== null;
    }

    /**
     * Get the AD roles for a given AD user based on keystone config.
     * Returns full Distinguished Names (DNs) of authorized groups.
     *
     * @param  \LdapRecord\Models\ActiveDirectory\User  $user
     * @param  string  $domain
     * @return array
     */
    public function getRolesForUser($adUser, string $domain): array
    {
        try {
            // Step 1: Retrieve AD group DNs
            $rawGroups = $adUser->groups()->get()->pluck('distinguishedname')->toArray();

            $userGroups = collect($rawGroups)
                ->flatten()
                ->filter(fn($g) => is_string($g) && !empty($g))
                ->map(fn($g) => strtolower(trim($g)))
                ->unique()
                ->values()
                ->toArray();

            // Step 2: Build final expected groups from keystone.php
            $accessControl = config('keystone.applicationAccessControl');

            $generalAccessGroups = [];
            $highPrivilegeGroups = [];

            if (isset($accessControl['generalAccessGroups'])) {
                $generalAccessGroups = array_map(
                    fn($g) => strtolower($this->resolveDnTemplate($g, $domain)),
                    $accessControl['generalAccessGroups']
                );
            }

            if (isset($accessControl['highPrivilegeGroups'])) {
                $highPrivilegeGroups = array_map(
                    fn($g) => strtolower($this->resolveDnTemplate($g, $domain)),
                    $accessControl['highPrivilegeGroups']
                );
            }

            // Step 3: Match user’s AD group DNs with config
            $hasGeneralAccess = count(array_intersect($userGroups, $generalAccessGroups)) > 0;
            $hasHighPrivilegeAccess = count(array_intersect($userGroups, $highPrivilegeGroups)) > 0;

            Log::info('User group evaluation', [
                'domain' => $domain,
                'baseDn' => $this->getBaseDn($domain), // Keep for logging context
                'userGroups' => $userGroups,
                'generalAccessGroups' => $generalAccessGroups,
                'highPrivilegeGroups' => $highPrivilegeGroups,
                'hasGeneralAccess' => $hasGeneralAccess,
                'hasHighPrivilegeAccess' => $hasHighPrivilegeAccess,
            ]);

            return [
                'roles' => $userGroups,
                'hasGeneralAccess' => $hasGeneralAccess,
                'hasHighPrivilegeAccess' => $hasHighPrivilegeAccess,
            ];
        } catch (\Exception $e) {
            Log::error("Failed to determine roles for AD user: " . $e->getMessage());
            return [
                'roles' => [],
                'hasGeneralAccess' => false,
                'hasHighPrivilegeAccess' => false,
            ];
        }
    }

    /**
     * Find a security group by its sAMAccountName on a specific domain.
     *
     * @param string $groupName
     * @param string $domain
     * @return LdapGroup|null
     */
    public function findGroupByName(string $groupName, string $domain): ?LdapGroup
    {
        try {
            $group = LdapGroup::on($domain)
                        ->where('samaccountname', '=', $groupName)
                        ->first();
            return $group;
        } catch (ModelNotFoundException $e) {
            return null;
        }
    }

    /**
     * Perform a health check on all configured AD domains.
     *
     * @return array
     */
    public function checkAdConnectivity(): array
    {
        $results = [];
        $domains = config('keystone.adSettings.domains', []);

        if (empty($domains)) {
            $domains = array_filter(explode(',', env('LDAP_DOMAINS', '')));
        }

        if (empty($domains)) {
            return ['status' => 'error', 'message' => 'No domains configured.'];
        }

        foreach ($domains as $domain) {
            try {
                $connection = Container::getConnection($domain);

                if ($connection->getLdapConnection()->isBound()) {
                    $results[$domain] = ['status' => 'success', 'message' => 'Successfully bound (cached connection).'];
                } else {
                    $connection->connect();
                    $results[$domain] = ['status' => 'success', 'message' => 'Successfully connected and bound with service account.'];
                }
            } catch (LdapRecordException $e) {
                Log::error("AD Health Check Failed for {$domain}: " . $e->getMessage());
                $results[$domain] = [
                    'status' => 'error',
                    'message' => $e->getMessage(),
                    'detail' => $e->getDetailedError() ? $e->getDetailedError()->getDiagnosticMessage() : 'No details'
                ];
            } catch (\Exception $e) {
                Log::error("AD Health Check Failed (General) for {$domain}: " . $e->getMessage());
                $results[$domain] = ['status' => 'error', 'message' => $e->getMessage()];
            }
        }

        return $results;
    }

    /**
     * Set or reset a user's password.
     *
     * @param LdapUser $user
     * @param string $password
     * @param bool $mustChange
     * @return void
     */
    public function resetPassword(LdapUser $user, string $password, bool $mustChange = true): void
    {
        try {
            $user->setAttribute('unicodePwd', $this->encodePassword($password));

            if ($mustChange) {
                $user->setAttribute('pwdLastSet', 0); // Force change on next login
            } else {
                $user->setAttribute('pwdLastSet', -1); // Do not expire
            }

            $user->save();

            Log::info("Password reset for user: {$user->getFirstAttribute('samaccountname')}");

        } catch (\Exception $e) {

            Log::error("Failed to reset password for user '{$user->getFirstAttribute('samaccountname')}': " . $e->getMessage());
            throw new \Exception("Password reset failed: " . $e->getMessage());
        }
    }

    /**
     * Create a new Active Directory user.
     * (Assumes $data contains snake_case keys from validation)
     *
     * @param array $data Validated data from CreateUserRequest
     * @return array ['user' => LdapUser, 'password' => string]
     */
    public function createUser(array $data): array
    {
        $result = $this->provisionAdUser($data, false);

        // Remap key for compatibility with UserController@store
        return [
            'user' => $result['user'],
            'password' => $result['initialPassword']
        ];
    }

    /**
     * Create a new privileged (admin) Active Directory user account.
     * (Assumes $data contains snake_case keys from validation)
     *
     * @param array $data
     * @return array
     */
    public function createAdminUser(array $data): array
    {
        // This function already returns 'initialPassword', so a direct call is fine.
        return $this->provisionAdUser($data, true);
    }

    /**
     * Update a user's details.
     * (Assumes $data contains camelCase keys from update validation)
     *
     * @param array $data Validated data from UpdateUserRequest
     * @return LdapUser
     */
    public function updateUser(array $data): array
    {
        $domain         = $data['domain'];
        $currentSam     = $data['samaccountname']; // From URL path
        $newSam         = $data['badgeNumber']; // From request body
        $cn             = Str::title($data['firstName'])." ".Str::title($data['lastName']);

        Log::info("Updating AD user '{$currentSam}' in domain '{$domain}'");

        try {
            $user = $this->findUserBySamAccountName($currentSam, $domain);
            if (!$user) {
                throw new ModelNotFoundException("User '{$currentSam}' not found in domain '{$domain}'.");
            }

            // --- Update Attributes (mirroring createUser) ---
            $user->samaccountname       = $newSam;
            $user->userprincipalname    = $newSam.'@'.$domain;
            $user->cn                   = $cn;
            $user->displayname          = $cn;
            $user->givenname            = Str::title($data['firstName']);
            $user->sn                   = Str::title($data['lastName']);
            $user->info                 = $data['dateOfBirth'];
            $user->mail                 = $newSam.'@'.$domain;
            $user->mobile               = $data['mobileNumber'];
            $user->accountExpires       = $this->convertDateToAdTimestamp($data['badgeExpirationDate']);

            $user->save();
            Log::info("User '{$currentSam}' updated successfully to '{$newSam}'.");

            // --- Group Logic (Add-Only) ---
            // This replicates the create logic (only adds, doesn't remove)
            $arrStandardGroups = $data['optionalGroupsForStandardUser'] ?? null;
            if (is_array($arrStandardGroups) && !empty($arrStandardGroups)) {
                foreach ($arrStandardGroups as $standardGroup) {
                    // addUserToGroup already checks if member exists
                    $this->addUserToGroup($domain, $user, $standardGroup);
                }
            }

            // --- Admin Account Logic ---
            $adminResult = null;
            $isPrivileged = !empty($data['createAdminAccount']);
            $canManageAdmin = !empty($data['hasHighPrivilegeAccess']);

            if ($isPrivileged && $canManageAdmin) {
                // We check based on the *new* samaccountname
                if ($this->checkIfAdminAccountExists($domain, $newSam)) {
                    Log::info("Admin account exists for '{$newSam}', updating...");
                    // updateAdminUser expects camelCase data, but also the original samaccountname
                    // We must provide the *original* samaccountname from the URL path for lookup
                    $data['samaccountname'] = $currentSam;
                    $adminResult = $this->updateAdminUser($data);
                } else {
                    Log::info("Admin account does not exist for '{$newSam}', creating...");
                    // createAdminUser expects snake_case, so we must map keys
                    $adminCreateData = [
                        'domain' => $data['domain'],
                        'badge_number' => $data['badgeNumber'],
                        'first_name' => $data['firstName'],
                        'last_name' => $data['lastName'],
                        'groups_privilege_user' => $data['optionalGroupsForHighPrivilegeUsers'] ?? []
                    ];
                    $adminResult = $this->createAdminUser($adminCreateData);
                }
            }

            return [
                'user' => $user,
                'admin_result' => $adminResult
            ];

        } catch (\Exception $e) {
            Log::error("Failed to update AD user '{$currentSam}': " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Update an existing privileged (admin) Active Directory user account.
     * (Assumes $data contains camelCase keys from update validation)
     *
     * @param array $data Validated data from UpdateUserRequest
     * @return LdapUser
     */
    public function updateAdminUser(array $data): array
    {
        $domain = $data['domain'];
        // Find admin user based on the *new* badge number
        $baseSam = $data['badgeNumber'];
        $adminSam = "{$baseSam}-a";

        // We must find the admin user based on the *original* samaccountname from the path
        $originalBaseSam = $data['samaccountname'];
        $originalAdminSam = "{$originalBaseSam}-a";

        $cn = "admin-".strtolower($data['firstName'].$data['lastName']);

        Log::info("Updating admin account '{$originalAdminSam}' to '{$adminSam}' in domain '{$domain}'");

        try {
            $adminUser = $this->findUserBySamAccountName($originalAdminSam, $domain);
            if (!$adminUser) {
                // This could happen if admin account was deleted manually.
                // We'll log a warning but not fail the whole standard user update.
                Log::warning("Admin user '{$originalAdminSam}' not found. Cannot update.");
                return ['user' => null];
            }

            // --- Update Attributes (mirroring createAdminUser) ---
            $adminUser->samaccountname       = $adminSam;
            $adminUser->userprincipalname    = $adminSam.'@'.$domain;
            $adminUser->cn                   = $cn;
            $adminUser->displayname          = $cn;
            $adminUser->givenname            = Str::title($data['firstName']);
            $adminUser->sn                   = Str::title($data['lastName']);
            $adminUser->accountExpires       = Carbon::now()->addMonth()->timestamp; // Admin accounts expire

            $adminUser->save();

            // --- Group Logic (Add-Only) ---
            // Add to any optional groups passed in the request
            $arrPrivilegeGroups = $data['optionalGroupsForHighPrivilegeUsers'] ?? null;
            if (is_array($arrPrivilegeGroups) && !empty($arrPrivilegeGroups)) {
                foreach ($arrPrivilegeGroups as $privilegeGroup) {
                    $this->addUserToGroup($domain, $adminUser, $privilegeGroup);
                }
            }

            // --- START: Ensure user is in default privilege group ---
            try {
                $groupTemplate = config('keystone.provisioning.ouPrivilegeUserGroup');
                if ($groupTemplate) {
                    $defaultPrivilegeGroupDn = $this->resolveDnTemplate($groupTemplate, $domain);
                    Log::info("Checking admin user membership in default privilege group: {$defaultPrivilegeGroupDn}");
                    $this->addUserToGroup($domain, $adminUser, $defaultPrivilegeGroupDn);
                } else {
                    Log::warning("keystone.provisioning.ouPrivilegeUserGroup is not defined in config.");
                }
            } catch (\Exception $e) {
                Log::error("Failed to add admin user to default privilege group during update: " . $e->getMessage());
            }
            // --- END: Add user to default privilege group from config ---

            return ['user' => $adminUser];

        } catch (\Exception $e) {
            Log::error("Failed to update admin user '{$originalAdminSam}': " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Disable a privileged admin account.
     *
     * @param string $domain
     * @param string $adminSam
     * @return void
     */
    public function disableAdminAccount(string $domain, string $adminSam): void
    {
        Log::info("Disabling admin account '{$adminSam}' in domain '{$domain}'.");
        $adminUser = $this->findUserBySamAccountName($adminSam, $domain);
        if ($adminUser) {
            $this->disableAccount($domain, $adminSam);
        } else {
            Log::warning("Could not disable admin account '{$adminSam}', user not found.");
        }
    }


    /**
     * Get details for a single user.
     *
     * @param string $domain
     * @param string $samAccountName
     * @return array|null
     */
    public function getUserDetails(string $domain, string $samAccountName): ?array
    {
        $user = $this->findUserBySamAccountName($samAccountName, $domain);

        if (!$user) {
            return null;
        }

        $dateOfBirth = $user->getFirstAttribute('info');
        $accountExpiresTimestamp = $user->getFirstAttribute('accountExpires');
        $accountExpires = 'Never';

        if ($accountExpiresTimestamp && $accountExpiresTimestamp > 0 && $accountExpiresTimestamp != '9223372036854775807') {
            try {
                // Convert Windows FileTime (100-nanosecond intervals since Jan 1, 1601) to Unix timestamp
                $unixTimestamp = ($accountExpiresTimestamp / 10000000) - 11644473600;
                $accountExpires = Carbon::createFromTimestamp($unixTimestamp)->toDateString();
            } catch (\Exception $e) {
                Log::warning("Could not parse accountExpires timestamp '{$accountExpiresTimestamp}' for user '{$samAccountName}'");
                $accountExpires = 'Invalid Date';
            }
        }


        return [
            'samAccountName' => $user->getFirstAttribute('samaccountname'),
            'firstName' => $user->getFirstAttribute('givenname'),
            'lastName' => $user->getFirstAttribute('sn'),
            'displayName' => $user->getFirstAttribute('displayname'),
            'userPrincipalName' => $user->getFirstAttribute('userprincipalname'),
            'emailAddress' => $user->getFirstAttribute('mail'),
            'dateOfBirth' => $dateOfBirth, // 'info' attribute
            'mobileNumber' => $user->getFirstAttribute('mobile'),
            'badgeExpirationDate' => $accountExpires,
            'isEnabled' => $user->isEnabled(),
            'isLockedOut' => ($user->getFirstAttribute('lockouttime') > 0) ? true : false,
            'memberOf' => $user->groups()->get()->pluck('samaccountname')->flatten()->all(),
            'hasAdminAccount' => str_ends_with($samAccountName, '-a')
                                    ? false // Admin accounts don't have *other* admin accounts
                                    : $this->checkIfAdminAccountExists($domain, $samAccountName)
        ];
    }

    /**
     * Converts a Y-m-d date string to an AD-compatible timestamp (Windows FileTime).
     *
     * @param string $dateString (Y-m-d)
     * @return string
     */
    private function convertDateToAdTimestamp(string $dateString): string
    {
        try {
            // Parse the date and set to end of day
            $carbonDate = Carbon::parse($dateString)->endOfDay();
            // Convert to Unix timestamp
            $unixTimestamp = $carbonDate->timestamp;
            // Convert to Windows FileTime (100-nanosecond intervals since Jan 1, 1601)
            $fileTime = ($unixTimestamp + 11644473600) * 10000000;
            return (string)$fileTime;
        } catch (\Exception $e) {
            Log::error("Failed to convert date '{$dateString}' to AD timestamp: " . $e->getMessage());
            // Fallback to a distant future date (approx 2038)
            return '21474836470000000';
        }
    }

    /**
     * List users based on filters.
     *
     * @param string $domain
     * @param string|null $nameFilter
     * @param bool|null $statusFilter
     * @param bool|null $hasAdminAccount
     * @return array
     */
    public function listUsers(string $domain, ?string $nameFilter, ?bool $statusFilter, ?bool $hasAdminAccount): array
    {
        $query = $this->newQuery($domain);

        // Define OUs to search from config
        $searchOus = config('keystone.provisioning.searchBaseOus', []);

        $formattedOus = array_map(fn($ou) => $this->resolveDnTemplate($ou, $domain), $searchOus);

        $users = collect();

        if (!empty($formattedOus)) {
            foreach ($formattedOus as $ou) {
                $subQuery = clone $query;
                $subQuery->in($ou);

                if (!empty($nameFilter)) {
                    $subQuery->where('displayname', 'contains', $nameFilter);
                }

                if ($statusFilter !== null) {
                    $statusFilter ? $subQuery->whereEnabled() : $subQuery->whereDisabled();
                }

                $users = $users->merge($subQuery->paginate(100));
            }
        } else {
            // fallback to default query if no OUs configured
            if (!empty($nameFilter)) {
                $query->where('displayname', 'contains', $nameFilter);
            }

            if ($statusFilter !== null) {
                $statusFilter ? $query->whereEnabled() : $query->whereDisabled();
            }

            $users = $query->paginate(100);
        }

        // Remove duplicates if search OUs overlap
        $users = $users->unique(function ($user) {
            return $user->getConvertedSid();
        });

        // Map results
        $userList = [];
        foreach ($users as $user) {
            $sam = $user->getFirstAttribute('samaccountname');
            // Skip admin accounts from this list
            if (Str::endsWith($sam, '-a')) {
                continue;
            }

            $adminExists = $this->checkIfAdminAccountExists($domain, $sam);

            if ($hasAdminAccount !== null && $adminExists !== $hasAdminAccount) {
                continue;
            }

            $userList[] = [
                'samAccountName'  => $sam,
                'displayName'     => $user->getFirstAttribute('displayname'),
                'isEnabled'       => $user->isEnabled(),
                'hasAdminAccount' => $adminExists,
            ];
        }

        return $userList;
    }

    /**
     * Reset the password for a privileged admin account.
     *
     * @param string $domain
     * @param string $baseSamAccountName
     * @return string The new password
     */
    public function resetAdminPassword(string $domain, string $baseSamAccountName): string
    {
        $adminSam = "{$baseSamAccountName}-a";
        $adminUser = $this->findUserBySamAccountName($adminSam, $domain);

        if (!$adminUser) {
            throw new ModelNotFoundException("Admin account '{$adminSam}' not found.");
        }

        $newPassword = $this->generatePassword();
        $this->resetPassword($adminUser, $newPassword, true);

        return $newPassword;
    }

    /**
     * Unlock a user account.
     *
     * @param string $domain
     * @param string $samAccountName
     * @return void
     */
    public function unlockAccount(string $domain, string $samAccountName): void
    {
        $user = $this->findUserBySamAccountName($samAccountName, $domain);
        if (!$user) {
            throw new ModelNotFoundException("User '{$samAccountName}' not found.");
        }

        if ($user->isLocked()) {
            $user->unlock();
            Log::info("Unlocked account for '{$samAccountName}'.");
        }
    }

    /**
     * Disable a user account.
     *
    * @param string $domain
     * @param string $samAccountName
     * @return void
     */
    public function disableAccount(string $domain, string $samAccountName): void
    {
        $user = $this->findUserBySamAccountName($samAccountName, $domain);
        if (!$user) {
            throw new ModelNotFoundException("User '{$samAccountName}' not found.");
        }

        if ($user->isEnabled()) {
            $user->disable();
            Log::info("Disabled account for '{$samAccountName}'.");
        }
    }

    /**
     * Enable a user account.
     *
     * @param string $domain
     * @param string $samAccountName
     * @return void
     */
    public function enableAccount(string $domain, string $samAccountName): void
    {
        $user = $this->findUserBySamAccountName($samAccountName, $domain);
        if (!$user) {
            throw new ModelNotFoundException("User '{$samAccountName}' not found.");
        }

        if ($user->isDisabled()) {
            $user->enable();
            Log::info("Enabled account for '{$samAccountName}'.");
        }
    }


}

