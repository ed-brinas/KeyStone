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
     * Remove a user from a specified Active Directory group.
     *
     * @param string $domain
     * @param LdapUser $user
     * @param string $groupName (This must be the full DN of the group)
     * @return bool
     */
    protected function removeUserFromGroup(string $domain, LdapUser $user, string $groupName): bool
    {
        try {
            Log::info("Attempting to remove '{$user->getName()}' from group '{$groupName}'...");

            $group = LdapGroup::on($domain)
                ->where('distinguishedname', '=', $groupName)
                ->first();

            if ($group) {
                if ($user->groups()->exists($group)) {
                    $group->members()->detach($user);
                    Log::info("Removed '{$user->getName()}' from group '{$groupName}'.");
                } else {
                    Log::info("'{$user->getName()}' is not a member of group '{$groupName}'.");
                }
                return true;
            }
            Log::warning("Group '{$groupName}' not found in domain '{$domain}'.");
        } catch (\Exception $e) {
            Log::error("Failed to remove '{$user->getName()}' from group '{$groupName}': " . $e->getMessage());
        }
        return false;
    }


    /**
     * Synchronizes a user's optional group memberships.
     *
     * @param string $domain
     * @param LdapUser $user
     * @param array $newGroupDns The list of group DNs the user *should* be in.
     * @param array $manageableGroupDns The list of *all* optional groups this function is allowed to manage.
     * @return void
     */
    protected function syncUserGroups(string $domain, LdapUser $user, array $newGroupDns, array $manageableGroupDns): void
    {
        try {
            // Normalize all DNs to lowercase for comparison
            $newGroupDns = array_map('strtolower', $newGroupDns);
            $manageableGroupDns = array_map('strtolower', $manageableGroupDns);

            $currentGroups = $user->groups()->get()
                ->pluck('distinguishedname')
                ->flatten() // <-- FIX: Flatten potential arrays of DNs
                ->filter(fn($g) => is_string($g) && !empty($g)) // <-- FIX: Ensure we only have non-empty strings
                ->map('strtolower')
                ->unique() // Add unique check for consistency
                ->toArray();

            // 1. Find groups to add
            $groupsToAdd = array_diff($newGroupDns, $currentGroups);
            foreach ($groupsToAdd as $groupDn) {
                // We only care about adding groups that are in the new list.
                $this->addUserToGroup($domain, $user, $groupDn);
            }

            // 2. Find groups to remove
            // These are groups the user is currently in, but are NOT in the new list.
            $groupsToRemove = array_diff($currentGroups, $newGroupDns);

            // 3. CRITICAL: Filter $groupsToRemove to only include groups we are allowed to manage.
            // We do not want to remove users from "Domain Users" or other essential groups
            // that aren't part of this optional list.
            $safeToRemove = array_intersect($groupsToRemove, $manageableGroupDns);

            foreach ($safeToRemove as $groupDn) {
                $this->removeUserFromGroup($domain, $user, $groupDn);
            }

        } catch (\Exception $e) {
            Log::error("Failed to sync groups for '{$user->getName()}': " . $e->getMessage());
        }
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
     * Converts a Y-m-d date string to an AD-compatible timestamp (Windows FileTime).
     *
     * @param string $dateString (Y-m-d)
     * @return string
     */
    protected function convertDateToAdTimestamp(string $dateString): string
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
     * Convert AD 'accountExpires' dateString to Y-m-d or 'Never'.
     *
     * @param string|int $dateString
     * @return string|null
     */
    protected function convertDateToTimestamp(string $dateTimeString): string
    {
        if ($dateTimeString == '0' || $dateTimeString >= '9223372036854775807') {
            return 'Never';
        }
        return Carbon::parse($dateTimeString)->format('Y-m-d H:i:s');
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
            // *** FIX: Use consistent AD timestamp for admin users ***
            $expires  = $this->convertDateToAdTimestamp(Carbon::now()->addMonth()->toDateString());
        } else {
            $cn       = $firstName." ".$lastName;
            $sam      = $data['badge_number'];
            $dn       = $this->buildDn($cn, $domain, false);
            $expires  = $this->convertDateToAdTimestamp($data['date_of_expiry']);
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

    /**
     * Updates an existing AD user (standard or admin).
     * (Assumes $data contains snake_case keys from validation)
     *
     * @param LdapUser $user The user object to update
     * @param array $data
     * @param boolean $isAdmin
     * @return LdapUser
     */
    protected function updateAdUser(LdapUser $user, array $data, bool $isAdmin = false): LdapUser
    {
        $domain = $data['domain'];
        $newSam = $data['badge_number'];
        $firstName = Str::title($data['first_name']);
        $lastName = Str::title($data['last_name']);
        $originalSam = $user->samaccountname[0];

        if ($isAdmin) {
            $sam = $newSam . '-a';
            $cn = "admin-" . strtolower($data['first_name'] . $data['last_name']);
            $expires = $this->convertDateToAdTimestamp(Carbon::now()->addMonth()->toDateString());
        } else {
            $sam = $newSam;
            $cn = $firstName . " " . $lastName;
            $expires = $this->convertDateToAdTimestamp($data['date_of_expiry']);
        }

        Log::info("Updating AD user '{$originalSam}' to '{$sam}' in domain '{$domain}'");

        $user->samaccountname = $sam;
        $user->userprincipalname = $sam . '@' . $domain;
        $user->cn = $cn;
        $user->displayname = $cn;
        $user->givenname = $firstName;
        $user->sn = $lastName;
        $user->accountExpires = $expires;

        // --- Standard-User-Only Attributes ---
        if (!$isAdmin) {
            $user->info = $data['date_of_birth'];
            $user->mail = $sam . '@' . $domain;
            $user->mobile = $data['mobile_number'];
        }

        $user->save();

        // --- Group Logic (Sync) ---
        if ($isAdmin) {
            // --- Admin Group Logic ---
            $newGroups = $data['groups_privilege_user'] ?? [];
            $allOptionalGroups = config('keystone.provisioning.optionalGroupsForHighPrivilegeUsers', []);
            $this->syncUserGroups($domain, $user, $newGroups, $allOptionalGroups);

            // --- START: Ensure user is in default privilege group ---
            try {
                $groupTemplate = config('keystone.provisioning.ouPrivilegeUserGroup');
                if ($groupTemplate) {
                    $defaultPrivilegeGroupDn = $this->resolveDnTemplate($groupTemplate, $domain);
                    Log::info("Checking admin user membership in default privilege group: {$defaultPrivilegeGroupDn}");
                    $this->addUserToGroup($domain, $user, $defaultPrivilegeGroupDn);
                } else {
                    Log::warning("keystone.provisioning.ouPrivilegeUserGroup is not defined in config.");
                }
            } catch (\Exception $e) {
                Log::error("Failed to add admin user to default privilege group during update: " . $e->getMessage());
            }
            // --- END: Add user to default privilege group from config ---
        } else {
            // --- Standard Group Logic ---
            $newGroups = $data['groups_standard_user'] ?? [];
            $allOptionalGroups = config('keystone.provisioning.optionalGroupsForStandardUser', []);
            $this->syncUserGroups($domain, $user, $newGroups, $allOptionalGroups);
        }

        return $user;
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
            $hasGeneralAccess = ($hasHighPrivilegeAccess > 0) ? $hasHighPrivilegeAccess : $hasGeneralAccess;

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
     * (Assumes $data contains snake_case keys from update validation)
     *
     * @param array $data Validated data from UpdateUserRequest
     * @return LdapUser
     */
    public function updateUser(array $data): array
    {
        // Use snake_case keys now, passed from controller
        $domain         = $data['domain'];
        // $currentSam     = $data['current_samaccountname']; // From URL path - NO LONGER USED FOR SEARCH
        $samToUpdate    = $data['badge_number']; // From request body, this is the key

        Log::info("Attempting to find and update AD user '{$samToUpdate}' in domain '{$domain}'");

        try {
            // *** MODIFIED LOGIC: Find user by badge_number from payload ***
            $user = $this->findUserBySamAccountName($samToUpdate, $domain);
            if (!$user) {
                // *** MODIFIED LOGIC: Throw error if not found ***
                throw new ModelNotFoundException("User '{$samToUpdate}' not found in domain '{$domain}'.");
            }

            // --- Update Standard User Attributes (call protected method) ---
            // This will update the user's info and sync standard groups
            $user = $this->updateAdUser($user, $data, false);
            Log::info("User '{$samToUpdate}' updated successfully.");


            // --- Admin Account Logic (Orchestration) ---
            $adminResult = null;
            $isPrivileged = !empty($data['has_admin']);
            $canManageAdmin = !empty($data['hasHighPrivilegeAccess']);

            if ($isPrivileged && $canManageAdmin) {
                // Admin SAM is based on the badge_number
                $adminSam = "{$samToUpdate}-a";
                $adminUser = $this->findUserBySamAccountName($adminSam, $domain);

                if ($adminUser) {
                    Log::info("Admin account '{$adminSam}' exists, updating...");
                    // Pass admin user and data
                    $adminResult = $this->updateAdminUser($adminUser, $data);
                } else {
                    Log::info("Admin account '{$adminSam}' does not exist, creating...");
                    // createAdminUser expects snake_case, which $data already is.
                    $adminResult = $this->createAdminUser($data);
                }
            } else if (!$isPrivileged && $canManageAdmin) {
                 // User *unchecked* the "has_admin" box. We should check if an admin account exists and,
                 // if so, *delete* it, as per the use case.
                 $adminSam = "{$samToUpdate}-a";
                 Log::info("has_admin is false. Checking if admin account '{$adminSam}' exists to delete it."); // MODIFIED LOG
                 if ($this->findUserBySamAccountName($adminSam, $domain)) {
                    $this->deleteAdminAccount($domain, $adminSam); // MODIFIED METHOD CALL
                    $adminResult = ['message' => "Admin account {$adminSam} deleted."]; // MODIFIED MESSAGE
                 }
            }

            return [
                'user' => $user,
                'admin_result' => $adminResult
            ];

        } catch (\Exception $e) {
            // Catch ModelNotFoundException from above
            if ($e instanceof ModelNotFoundException) {
                Log::warning($e->getMessage());
                throw $e;
            }
            Log::error("Failed to update AD user '{$samToUpdate}': " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Update an existing privileged (admin) Active Directory user account.
     * (Assumes $data contains snake_case keys from update validation)
     *
     * @param LdapUser $adminUser The admin user LdapUser object
     * @param array $data Validated data from UpdateUserRequest
     * @return LdapUser
     */
    public function updateAdminUser(LdapUser $adminUser, array $data): array
    {
        $originalAdminSam = $adminUser->samaccountname[0]; // Get from object
        Log::info("Updating admin account '{$originalAdminSam}' in domain '{$data['domain']}' via protected method.");

        try {
            // --- Call the new protected method for the admin user ---
            $adminUser = $this->updateAdUser($adminUser, $data, true);

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
            $this->disableAccount($domain, $adminSam); // Re-use existing disable logic
        } else {
            Log::warning("Could not disable admin account '{$adminSam}', user not found.");
        }
    }

    /**
     * Delete a privileged admin account.
     *
     * @param string $domain
     * @param string $adminSam
     * @return void
     */
    public function deleteAdminAccount(string $domain, string $adminSam): void
    {
        Log::info("Deleting admin account '{$adminSam}' in domain '{$domain}'.");
        $adminUser = $this->findUserBySamAccountName($adminSam, $domain);
        if ($adminUser) {
            try {
                $adminUser->delete();
                Log::info("Admin account '{$adminSam}' deleted successfully.");
            } catch (\Exception $e) {
                Log::error("Failed to delete admin account '{$adminSam}': " . $e->getMessage());
                // Re-throw exception to be caught by the controller
                throw $e;
            }
        } else {
            Log::warning("Could not delete admin account '{$adminSam}', user not found.");
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
        $accountExpiresValue = $user->getFirstAttribute('accountExpires');
        $accountExpires = 'Never';

        // Check if LdapRecord already gave us a Carbon object
        if ($accountExpiresValue instanceof \Carbon\Carbon) {
            // It's a Carbon object. Check if it's a "never" date.
            // LDAP "never" dates are often far in the future or near epoch '0'.
            if ($accountExpiresValue->year > 9000 || $accountExpiresValue->timestamp < 1) {
                $accountExpires = 'Never';
            } else {
                $accountExpires = $accountExpiresValue->toDateString();
            }
        } 
        // Check for the raw numeric/string values (the original logic)
        else if (is_numeric($accountExpiresValue) && $accountExpiresValue > 0 && $accountExpiresValue != '9223372036854775807') {
            try {
                // It's a raw Windows FileTime. Convert it.
                $unixTimestamp = ($accountExpiresValue / 10000000) - 11644473600;
                $accountExpires = Carbon::createFromTimestamp($unixTimestamp)->toDateString();
            } catch (\Exception $e) {
                Log::warning("Could not parse accountExpires timestamp '{$accountExpiresValue}' for user '{$samAccountName}'");
                $accountExpires = 'Invalid Date';
            }
        }
        // *** END FIX ***

        // --- START: Logic modification for admin groups ---

        // 1. Determine if an admin account exists
        $hasAdminAccount = str_ends_with($samAccountName, '-a')
                                ? false // Admin accounts don't have *other* admin accounts
                                : $this->checkIfAdminAccountExists($domain, $samAccountName);

        // 2. Get the default memberOf from the *standard* user first (Reverted change)
        $memberOf = $user->groups()->get()->pluck('distinguishedname')->flatten()->filter()->all();

        // 3. (ADJUSTMENT) Add a new key 'memberOfAdmin' if admin account exists
        $memberOfAdmin = []; // Default to empty array
        if ($hasAdminAccount) {
            $adminSam = $samAccountName . '-a';
            $adminUser = $this->findUserBySamAccountName($adminSam, $domain);

            if ($adminUser) {
                Log::info("User '{$samAccountName}' has admin account. Fetching groups for '{$adminSam}'.");
                // Populate the new array with admin groups
                $memberOfAdmin = $adminUser->groups()->get()->pluck('distinguishedname')->flatten()->filter()->all();
            } else {
                // This case is unlikely if $hasAdminAccount is true, but good to handle.
                Log::warning("User '{$samAccountName}' hasAdminAccount=true, but admin user '{$adminSam}' could not be found to fetch groups.");
                // $memberOfAdmin remains an empty array
            }
        }
        // --- END: Logic modification for admin groups ---


        return [
            'samAccountName' => $user->getFirstAttribute('samaccountname'),
            'firstName' => $user->getFirstAttribute('givenname'),
            'lastName' => $user->getFirstAttribute('sn'),
            'displayName' => $user->getFirstAttribute('displayname'),
            'userPrincipalName' => $user->getFirstAttribute('userprincipalname'),
            'emailAddress' => $user->getFirstAttribute('mail'),
            'dateOfBirth' => $dateOfBirth, // 'info' attribute
            'mobileNumber' => $user->getFirstAttribute('mobile'),
            'badgeExpirationDate' => $accountExpires, // Use the new, safer variable
            'isEnabled' => $user->isEnabled(),
            'isLockedOut' => ($user->getFirstAttribute('lockouttime') > 0) ? true : false,
            'memberOf' => $memberOf, // This is now correctly the *standard* user's groups
            'memberOfAdmin' => $memberOfAdmin, // This new field holds the admin groups
            'hasAdminAccount' => $hasAdminAccount
        ];
    }

    /**
     * List users based on filters.
     *
     * @param string $searcg
     * @param string|null $nameFilter
     * @param bool|null $statusFilter
     * @param bool|null $hasAdminAccount
     * @return array
     */
    public function listUsers(?string $domainFilter = null, ?string $nameFilter = null): array
    {
        $searchOus = config('keystone.provisioning.searchBaseOus', []);
        $formattedOus = array_map(fn($ou) => $this->resolveDnTemplate($ou, $domainFilter), $searchOus);
        
        $finalUsers = collect();

        foreach ($formattedOus as $formattedOu) {
            $query = LdapUser::in($formattedOu);
            
            if ($nameFilter) {
                $query->where('anr', '=', $nameFilter);
            }
            
            $extractedInfo = $query->get()->map(function ($ldapUser) use ($domainFilter) {
                preg_match_all('/DC=([^,]+)/i', $ldapUser->getDn(), $matches);
                $domain = implode('.', $matches[1] ?? []);

                return [
                    'displayName' => $ldapUser->getName(),
                    'domain' => $domain,
                    'isEnabled' => $ldapUser->isEnabled(),
                    'samAccountName' => $ldapUser->getFirstAttribute('userprincipalname'),
                    'accountExpires' => $this->convertDateToTimestamp($ldapUser->getFirstAttribute('accountexpires')),
                    'hasAdminAccount' => $this->checkIfAdminAccountExists($domain, $ldapUser->getFirstAttribute('samaccountname'))
                ];
            });            

            $finalUsers = $finalUsers->merge($extractedInfo);
        }
        
        if ($domainFilter) {
            $finalUsers = $finalUsers->where('domain', $domainFilter);
        }

        return $finalUsers->values()->all();
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