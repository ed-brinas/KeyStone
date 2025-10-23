<?php

namespace App\Services;

use LdapRecord\Container;
use LdapRecord\LdapRecordException;
use LdapRecord\Connection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use LdapRecord\Models\ActiveDirectory\User as LdapUser;
use LdapRecord\Models\ActiveDirectory\Group as LdapGroup;
use LdapRecord\Models\ModelNotFoundException;
use Illuminate\Support\Str;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;

class AdService
{
    /**
     * Get the base DN for a specific domain from keystone config.
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
    public function newQuery(string $domain): \LdapRecord\Query\Model\Builder
    {
        return LdapUser::on($domain);
    }


    // --- STABLE METHODS (DO NOT TOUCH) ---

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
        Log::debug("Attempting to find user by sAMAccountName: {$username}");
        try {
            $query = $this->newQuery($domain);
            $user = $query->where('samaccountname', '=', $username)->first();
            
            if (!$user) {
                return null;
                Log::debug('User not found.');
            } 

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
     * Get the AD roles for a given AD user based on keystone config.
     * User must be a member of *either* a general OR a high privilege group to get access.
     *
     * @param LdapUser $user
     * @param string $domain
     * @return array
     */
    public function getRolesForUser(LdapUser $user, string $domain): array
    {
        $generalAccessGroups = config('keystone.applicationAccessControl.generalAccessGroups', []);
        $highPrivilegeGroups = config('keystone.applicationAccessControl.highPrivilegeGroups', []);
        
        $userRoles = [];
        $hasGeneralAccess = false;
        $hasHighPrivilegeAccess = false;
        
        $domainDn = $this->getBaseDn($domain);
        Log::debug("Role Check: Base DN created: '{$domainDn}'");

        // Get all of the user's AD groups (reads the 'memberOf' attribute)
        $userGroups = $user->groups()->get();
        Log::debug("Role Check: User '{$user->getFirstAttribute('samaccountname')}' is a member of " . count($userGroups) . " groups.");

        foreach ($userGroups as $group) {
            $groupName = $group->getFirstAttribute('samaccountname');
            $groupDn = $group->getDn();
            if (empty($groupName) || empty($groupDn)) continue;

            Log::debug("Role Check: Processing group '{$groupName}' with DN '{$groupDn}'");

            $isAccessGroup = false;

            // Check if this group is a General Access group
            foreach ($generalAccessGroups as $configGroup) {
                $formattedConfigGroup = str_replace('{domain-components}', $domainDn, $configGroup);
                Log::debug("Role Check: Comparing (General) '{$groupDn}' (User) VS '{$formattedConfigGroup}' (Config)");
                if (strcasecmp($groupDn, $formattedConfigGroup) === 0) {
                    Log::debug("Role Check: MATCH! User has General Access via '{$groupName}'");
                    $hasGeneralAccess = true;
                    $isAccessGroup = true;
                    break;
                }
            }

            // Check if this group is a High Privilege group (only if not already found in general)
            if (!$isAccessGroup) {
                foreach ($highPrivilegeGroups as $configGroup) {
                    $formattedConfigGroup = str_replace('{domain-components}', $domainDn, $configGroup);
                    Log::debug("Role Check: Comparing (High) '{$groupDn}' (User) VS '{$formattedConfigGroup}' (Config)");
                    if (strcasecmp($groupDn, $formattedConfigGroup) === 0) {
                        Log::debug("Role Check: MATCH! User has High Privilege Access via '{$groupName}'");
                        $hasHighPrivilegeAccess = true;
                        $isAccessGroup = true;
                        break;
                    }
                }
            }

            // NOW, if it was an access group, add its name to the roles list
            if ($isAccessGroup) {
                // We no longer check Spatie, just add the AD group name
                // NORMALIZE TO LOWERCASE
                $userRoles[] = strtolower($groupName);
                Log::debug("Role Check: Added AD Group '{$groupName}' (normalized) to token abilities.");
            }
        }
        
        // Per requirement: user MUST be part of *either* general OR high privilege groups
        Log::debug("Role Check: Final decision: hasGeneralAccess=($hasGeneralAccess), hasHighPrivilegeAccess=($hasHighPrivilegeAccess)");
        if ($hasGeneralAccess || $hasHighPrivilegeAccess) {
            // Add 'default' role if it's not there
            if (!in_array('default', $userRoles)) {
                 $userRoles[] = 'default';
                 Log::debug("Role Check: Added 'default' role.");
            }
            
            Log::debug("Role Check: Access GRANTED. Roles: " . implode(', ', $userRoles));
            return array_unique($userRoles);
        }

        // If requirement is not met, return no roles.
        // This will cause the login to fail in AuthController.
        Log::warning("User '{$user->getFirstAttribute('samaccountname')}' login denied. Does not meet General OR High Privilege group requirements.");
        return [];
    }

    // --- END STABLE METHODS ---


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
     * Generate a secure, random password.
     * Logic ported from AdService.cs GeneratePassword()
     *
     * @return string
     */
    public function generatePassword(): string
    {
        $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lower = 'abcdefghijkmnpqrstuvwxyz';
        $number = '23456789';
        $special = '*$-+?_&=!%{}/';

        $allChars = $upper . $lower . $number . $special;

        $password = '';
        $password .= $upper[random_int(0, strlen($upper) - 1)];
        $password .= $lower[random_int(0, strlen($lower) - 1)];
        $password .= $number[random_int(0, strlen($number) - 1)];
        $password .= $special[random_int(0, strlen($special) - 1)];

        for ($i = 0; $i < 12; $i++) {
            $password .= $allChars[random_int(0, strlen($allChars) - 1)];
        }

        // --- FIX: Use str_shuffle instead of Str::shuffle ---
        return str_shuffle($password);
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
        $domainDn = $this->getBaseDn($domain);
        $ou = str_replace('{domain-components}', $domainDn, $ouTemplate);

        return "CN=$cn,$ou";
    }

    /**
     * Add a user to a security group.
     *
     * @param LdapUser $user
     * @param string $groupName
     * @param string $domain
     * @return void
     */
    public function addUserToGroup(LdapUser $user, string $groupName, string $domain): void
    {
        try {
            $group = $this->findGroupByName($groupName, $domain);
            if ($group) {
                $user->groups()->attach($group);
                // --- FIX: Use getFirstAttribute ---
                Log::info("Added user '{$user->getFirstAttribute('samaccountname')}' to group '{$groupName}'.");
            } else {
                Log::warning("Could not add user to group. Group '{$groupName}' not found in domain '{$domain}'.");
            }
        } catch (\Exception $e) {
            // --- FIX: Use getFirstAttribute ---
            Log::error("Failed to add user '{$user->getFirstAttribute('samaccountname')}' to group '{$groupName}': " . $e->getMessage());
        }
    }

    /**
     * Remove a user from a security group.
     *
     * @param LdapUser $user
     * @param string $groupName
     * @param string $domain
     * @return void
     */
    public function removeUserFromGroup(LdapUser $user, string $groupName, string $domain): void
    {
        try {
            $group = $this->findGroupByName($groupName, $domain);
            if ($group) {
                $user->groups()->detach($group);
                // --- FIX: Use getFirstAttribute ---
                Log::info("Removed user '{$user->getFirstAttribute('samaccountname')}' from group '{$groupName}'.");
            } else {
                Log::warning("Could not remove user from group. Group '{$groupName}' not found in domain '{$domain}'.");
            }
        } catch (\Exception $e) {
            // --- FIX: Use getFirstAttribute ---
            Log::error("Failed to remove user '{$user->getFirstAttribute('samaccountname')}' from group '{$groupName}': " . $e->getMessage());
        }
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
     *
     * @param array $data Validated data from CreateUserRequest
     * @return array ['user' => LdapUser, 'password' => string]
     */
    public function createUser(array $data): array
    {
        $domain = $data['domain'];
        $sam = $data['samAccountName'];
        $cn = $data['firstName'] . ' ' . $data['lastName'];
        $isPrivileged = $data['createAdminAccount'] ?? false;

        Log::info("Attempting to create user '{$sam}' in domain '{$domain}'. IsPrivileged: " . ($isPrivileged ? 'Yes' : 'No'));

        try {
            // --- 1. Create minimal user object ---
            $dn = $this->buildDn($cn, $domain, $isPrivileged);
            $user = new LdapUser();
            $user->setConnection($domain);
            $user->setDn($dn);

            $user->setAttribute('cn', $cn);
            $user->setAttribute('samaccountname', $sam);
            $user->setAttribute('sn', $data['lastName']);
            $user->setAttribute('givenname', $data['firstName']);
            $user->setAttribute('displayname', $cn);
            $user->setAttribute('userprincipalname', "{$sam}@{$domain}");
            $user->setAttribute('objectClass', ['top', 'person', 'organizationalPerson', 'user']);
            $user->setAttribute('userAccountControl', 544); // Disabled account

            $user->save();
            Log::info("LDAP: Created minimal user object '{$sam}' successfully.");

            // --- 2. Add optional attributes (safe) ---
            $user->refresh();
            $attributes = [];

            if (!empty($data['mobileNumber'])) {
                $attributes['mobile'] = $data['mobileNumber'];
            }
            if (!empty($data['email'])) {
                $attributes['mail'] = $data['email'];
            }

            foreach ($attributes as $attr => $value) {
                try {
                    $user->setAttribute($attr, $value);
                    $user->save();
                    Log::info("Set optional attribute '{$attr}' for '{$sam}'.");
                } catch (\Exception $ex) {
                    Log::warning("Could not set attribute '{$attr}' for '{$sam}': " . $ex->getMessage());
                }
            }

            // --- 3. Set password and enable ---
            $initialPassword = $this->generatePassword();
            try {
                $this->resetPassword($user, $initialPassword, true);
                $user->setAttribute('userAccountControl', 512); // Normal account
                $user->save();
                Log::info("Password set and account enabled for '{$sam}'.");
            } catch (\Exception $e) {
                Log::error("Failed to reset password for '{$sam}': " . $e->getMessage());
                throw new \Exception("Password reset failed: " . $e->getMessage());
            }

            // --- 4. Group membership handling (safe existence check) ---
            $optionalGroups = $data['optionalGroupsForStandardUser'] ?? [];
            foreach ($optionalGroups as $groupName) {
                try {
                    $group = LdapGroup::on($domain)
                        ->where('samaccountname', '=', $groupName)
                        ->first(); // Get actual model instance

                    if (!$group) {
                        Log::warning("Group '{$groupName}' not found in domain '{$domain}'. Skipping...");
                        continue;
                    }

                    $group->members()->attach($user);
                    Log::info("Added user '{$sam}' to group '{$groupName}' successfully.");

                } catch (\LdapRecord\Exceptions\LdapException $ex) {
                    Log::error("Failed to add user '{$sam}' to group '{$groupName}': " . $ex->getMessage());
                } catch (\Exception $ex) {
                    Log::error("Unexpected error adding '{$sam}' to '{$groupName}': " . $ex->getMessage());
                }
            }

            // --- 5. Privileged account (if needed) ---
            $adminAccountData = null;
            if ($isPrivileged) {
                $adminAccountData = $this->createAdminAccount($domain, $data);
            }

            return [
                'user' => $user,
                'password' => $initialPassword,
                'adminAccount' => $adminAccountData
            ];

        } catch (\LdapRecord\Exceptions\LdapException $e) {
            Log::error("LDAP error creating user '{$sam}': " . $e->getMessage());
            throw new \Exception("LDAP error: " . $e->getMessage());
        } catch (\Exception $e) {
            Log::error("Failed to create user '{$sam}': " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Check if a corresponding admin account exists.
     *
     * @param string $domain
     * @param string $baseSamAccountName
     * @return bool
     */
    public function checkIfAdminAccountExists(string $domain, string $baseSamAccountName): bool
    {
        return $this->findUserBySamAccountName("{$baseSamAccountName}-a", $domain) !== null;
    }

    /**
     * Create a privileged admin account.
     *
     * @param string $domain
     * @param array $baseRequestData
     * @return array
     */
    public function createAdminAccount(string $domain, array $baseRequestData): array
    {
        $adminSam = "{$baseRequestData['samAccountName']}-a";
        Log::info("Creating admin account '{$adminSam}' in domain '{$domain}'.");

        try {
            // --- FIX: Use new LdapUser() and setConnection ---
            $adminUser = new LdapUser();
            $adminUser->setConnection($domain);

            // Build DN using the privileged OU
            $dn = $this->buildDn($baseRequestData['firstName'] . ' ' . $baseRequestData['lastName'] . ' (Admin)', $domain, true);
            $adminUser->setDn($dn);
            
            $adminUser->setAttribute('samaccountname', $adminSam);
            $adminUser->setAttribute('displayname', $baseRequestData['firstName'] . ' ' . $baseRequestData['lastName'] . ' (Admin)');
            $adminUser->setAttribute('userprincipalname', $adminSam . '@' . $domain);
            $adminUser->setAttribute('userAccountControl', 512); // 512 = Normal Account

            $adminPassword = $this->generatePassword();
            $this->resetPassword($adminUser, $adminPassword, true);

            // Add to privileged groups
            $privilegeGroups = $baseRequestData['optionalGroupsForHighPrivilegeUsers'] ?? [];
            
            // Set Primary Group (if groups are provided)
            if (!empty($privilegeGroups)) {
                $firstGroup = $this->findGroupByName($privilegeGroups[0], $domain);
                if ($firstGroup) {
                    $adminUser->setPrimaryGroup($firstGroup);
                    // --- FIX: Use getFirstAttribute ---
                    Log::info("Set primary group for '{$adminSam}' to '{$firstGroup->getFirstAttribute('samaccountname')}'.");
                }
            }
            
            // Add to all specified privilege groups
            foreach ($privilegeGroups as $groupName) {
                $this->addUserToGroup($adminUser, $groupName, $domain);
            }

            // Remove from 'Domain Users'
            $this->removeUserFromGroup($adminUser, 'Domain Users', $domain);

            return [
                'samAccountName' => $adminSam,
                'initialPassword' => $adminPassword
            ];
        } catch (\Exception $e) {
            Log::error("Failed to create admin account '{$adminSam}': " . $e->getMessage());
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
     * Update group membership for a user.
     *
     * @param LdapUser $user
     * @param string $domain
     * @param array $requestedGroups
     * @param array $manageableGroups
     * @return void
     */
    public function updateGroupMembership(LdapUser $user, string $domain, array $requestedGroups, array $manageableGroups): void
    {
        // Get user's current groups that are in the manageable list
        $currentGroups = $user->groups()
                            ->get()
                            ->whereIn('samaccountname', $manageableGroups)
                            ->pluck('samaccountname')
                            ->map(fn ($name) => strtolower($name))
                            ->all();
        
        $requestedGroups = (new Collection($requestedGroups))->map(fn ($name) => strtolower($name));

        $groupsToAdd = $requestedGroups->diff($currentGroups)->all();
        $groupsToRemove = (new Collection($currentGroups))->diff($requestedGroups)->all();

        foreach ($groupsToAdd as $groupName) {
            $this->addUserToGroup($user, $groupName, $domain);
        }

        foreach ($groupsToRemove as $groupName) {
            $this->removeUserFromGroup($user, $groupName, $domain);
        }
    }

    /**
     * Update a user's details.
     *
     * @param string $domain
     * @param string $samAccountName
     * @param array $data Validated data from UpdateUserRequest
     * @return LdapUser
     */
    public function updateUser(string $domain, string $samAccountName, array $data): LdapUser
    {
        $user = $this->findUserBySamAccountName($samAccountName, $domain);
        if (!$user) {
            throw new ModelNotFoundException("User '{$samAccountName}' not found.");
        }

        Log::info("Updating user '{$samAccountName}' in domain '{$domain}'.");

        // Update attributes
        // LdapRecord automatically clears attributes if value is null or empty array
        $user->setAttribute('extensionAttribute1', $data['dateOfBirth'] ?? null);
        $user->setAttribute('mobile', $data['mobileNumber'] ?? null);
        $user->save();

        // Update standard group memberships
        $standardGroups = config('keystone.provisioning.optionalGroupsForStandardUser', []);
        $this->updateGroupMembership($user, $domain, $data['optionalGroups'] ?? [], $standardGroups);

        // Handle admin account creation/disabling
        $adminExists = $this->checkIfAdminAccountExists($domain, $samAccountName);
        
        if (isset($data['hasAdminAccount'])) {
            if ($data['hasAdminAccount'] && !$adminExists) {
                // Create admin account
                Log::info("UpdateUser: Creating admin account for '{$samAccountName}'.");
                $adminData = [
                    'samAccountName' => $samAccountName,
                    'firstName' => $user->getFirstAttribute('givenname'),
                    'lastName' => $user->getFirstAttribute('sn'),
                    'optionalGroupsForHighPrivilegeUsers' => config('keystone.provisioning.optionalGroupsForHighPrivilegeUsers', [])
                ];
                $this->createAdminAccount($domain, $adminData);
            } elseif (!$data['hasAdminAccount'] && $adminExists) {
                // Disable admin account
                Log::info("UpdateUser: Disabling admin account for '{$samAccountName}'.");
                $this.disableAdminAccount($domain, "{$samAccountName}-a");
            }
        }
        
        return $user;
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

        return [
            'samAccountName' => $user->getFirstAttribute('samaccountname'),
            'firstName' => $user->getFirstAttribute('givenname'),
            'lastName' => $user->getFirstAttribute('sn'),
            'displayName' => $user->getFirstAttribute('displayname'),
            'userPrincipalName' => $user->getFirstAttribute('userprincipalname'),
            'emailAddress' => $user->getFirstAttribute('mail'),
            'dateOfBirth' => $user->getFirstAttribute('extensionAttribute1'),
            'mobileNumber' => $user->getFirstAttribute('mobile'),
            'isEnabled' => $user->isEnabled(),
            'isLockedOut' => ($user->getFirstAttribute('lockouttime') > 0) ? true : false,
            'memberOf' => $user->groups()->get()->pluck('samaccountname')->flatten()->all(),
            'hasAdminAccount' => $this->checkIfAdminAccountExists($domain, $samAccountName)
        ];
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
        $domainDn = $this->getBaseDn($domain);
        $formattedOus = array_map(fn($ou) => str_replace('{domain-components}', $domainDn, $ou), $searchOus);

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

        // Map results
        $userList = [];
        foreach ($users as $user) {
            $sam = $user->getFirstAttribute('samaccountname');
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
