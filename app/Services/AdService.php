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

            // Step 2: Use the helper to get DN-form domain components
            $baseDn = $this->getBaseDn($domain);

            // Step 3: Build final expected groups from keystone.php
            $accessControl = config('keystone.applicationAccessControl');

            $generalAccessGroups = [];
            $highPrivilegeGroups = [];

            if (isset($accessControl['generalAccessGroups'])) {
                $generalAccessGroups = array_map(
                    fn($g) => strtolower(str_replace('{domain-components}', $baseDn, $g)),
                    $accessControl['generalAccessGroups']
                );
            }

            if (isset($accessControl['highPrivilegeGroups'])) {
                $highPrivilegeGroups = array_map(
                    fn($g) => strtolower(str_replace('{domain-components}', $baseDn, $g)),
                    $accessControl['highPrivilegeGroups']
                );
            }

            // Step 4: Match user’s AD group DNs with config
            $hasGeneralAccess = count(array_intersect($userGroups, $generalAccessGroups)) > 0;
            $hasHighPrivilegeAccess = count(array_intersect($userGroups, $highPrivilegeGroups)) > 0;

            Log::info('User group evaluation', [
                'domain' => $domain,
                'baseDn' => $baseDn,
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
     * Add a user to a specified Active Directory group.
     *
     * @param string $domain
     * @param LdapUser $user
     * @param string $groupName
     * @return bool
     */
    protected function addUserToGroup(string $domain, LdapUser $user, string $groupName): bool
    {
        try {
            Log::info("Adding '{$user}' to group...");

            $group = LdapGroup::on($domain)
                ->where('distinguishedname', '=', $groupName)
                ->first();

            if ($group) {
                $group->members()->attach($user);
                Log::info("Added '{$user->getName()}' to group '{$groupName}'.");
                return true;
            }

            Log::warning("Group '{$groupName}' not found in domain '{$domain}'.");

        } catch (\Exception $e) {
            Log::error("Failed to add '{$user->getName()}' to group '{$groupName}': " . $e->getMessage());
        }

        return false;
    }

    /**
     * Remove a user from a security group.
     *
     * @param LdapUser $user
     * @param string $groupName
     * @param string $domain
     * @return void
     */
    protected function removeUserFromGroup(string $domain, LdapUser $user, string $groupName): bool
    {
        try {
            $group = LdapGroup::on($domain)
                ->where('samaccountname', '=', $groupName)
                ->first();

            if ($group && $group->members()->exists($user)) {
                $group->members()->detach($user);
                Log::info("Removed '{$user->getName()}' from group '{$groupName}'.");
                return true;
            }

            Log::debug("Group '{$groupName}' not found or user '{$user->getName()}' not a member.");
        } catch (\Exception $e) {
            Log::error("Failed to remove '{$user->getName()}' from group '{$groupName}': " . $e->getMessage());
        }

        return false;
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
        Log::debug('User provisioning data:', $data);

        $domain         = $data['domain'];
        $cn             = Str::title($data['first_name'])." ".Str::title($data['last_name']);
        $dn             = $this->buildDn($cn, $domain, false);

        try {

            // 1. Build DN and create base user object
            $user                       = new LdapUser;
            $user->cn                   = $cn;
            $user->samaccountname       = $data['badge_number'];
            $user->userprincipalname    = $data['badge_number'].'@'.$domain;
            $user->displayname          = $cn;
            $user->givenname            = Str::title($data['first_name']);
            $user->sn                   = Str::title($data['last_name']);
            $user->info                 = $data['date_of_birth'];
            $user->mail                 = $data['badge_number'].'@'.$domain;
            $user->mobile               = $data['mobile_number'];
            $user->useraccountcontrol   = 544;
            $user->accountExpires       = strtotime($data['badge_expiration_date']);
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
            $arrStandardGroups = $data['groups_standard_user'] ?? null;
            if (is_array($arrStandardGroups) && !empty($arrStandardGroups)) {
                foreach ($arrStandardGroups as $standardGroup) {
                    $this->addUserToGroup($domain, $user, $standardGroup);
                }                
            }

            return [
                'user' => $user ?? null,
                'password' => $initialPassword ?? null,
            ];

        } catch (\Exception $e) {
            Log::error('User creation failed: ' . $e->getMessage());
            throw $e;
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
    public function updateUser(array $data): array
    {
        $domain         = $data['domain'];
        $sam            = $data['badgeNumber'];
        $cn             = "{$data['firstName']} {$data['lastName']}";
        $isPrivileged   = !empty($data['createAdminAccount']);

        Log::info("Updating AD user '{$sam}' in domain '{$domain}'");

        try {
            $user = $this->findUserBySamAccountName($sam, $domain);
            if (!$user) {
                throw new \Exception("User '{$sam}' not found in domain '{$domain}'.");
            }

            $updates = [
                'displayName' => Str::title($cn),
                'givenName' => Str::title($data['firstName']),
                'sn' => Str::title($data['lastName']),
                'info' => $data['dateOfBirth'],
                'mail' => "{$data['badgeNumber']}@{$domain}",
                'mobile' => $data['mobileNumber'],
                'accountExpires' => strtotime($data['badgeExpirationDate']),
            ];

            foreach ($updates as $attr => $value) {
                try {
                    $user->setAttribute($attr, $value);
                } catch (\Exception $e) {
                    Log::warning("Failed updating attribute '{$attr}' for '{$sam}': " . $e->getMessage());
                }
            }

            $user->save();
            Log::info("User '{$sam}' updated successfully.");

            // Update admin account if applicable
            if ($isPrivileged) {
                $adminData = $this->checkIfAdminAccountExists($domain, $sam)
                    ? $this->updateAdminUser($domain, $data)
                    : $this->createAdminUser($domain, $data);
            }

            return ['user' => $user];
        } catch (\Exception $e) {
            Log::error("Failed to update AD user '{$sam}': " . $e->getMessage());
            throw $e;
        }

    }

    /**
     * Create a new privileged (admin) Active Directory user account.
     *
     * @param string $domain
     * @param array $baseRequestData
     * @return array
     */
    public function createAdminUser(array $data): array
    {
        $domain         = $data['domain'];
        $cn             = "admin-".strtolower($data['first_name'].$data['last_name']);
        $dn             = $this->buildDn($cn, $domain, true);

        try {

            $user                       = new LdapUser;
            $user->cn                   = $cn;
            $user->samaccountname       = $data['badge_number'];
            $user->userprincipalname    = $data['badge_number'].'-a@'.$domain;
            $user->displayname          = $cn;
            $user->givenname            = Str::title($data['first_name']);
            $user->sn                   = Str::title($data['last_name']);
            $user->useraccountcontrol   = 544;
            $user->accountExpires       = Carbon::now()->addMonth()->timestamp;
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
            $isFirstGroup = true;
            $arrStandardGroups = $data['groups_standard_user'] ?? null;
            if (is_array($arrStandardGroups) && !empty($arrStandardGroups)) {
                foreach ($arrStandardGroups as $standardGroupDN) { // Renamed variable for clarity
                    
                    // Find the group object by its DN
                    $group = LdapGroup::on($domain)
                                ->where('distinguishedname', '=', $standardGroupDN)
                                ->first();

                    if ($group) {
                        // Add the user to the group
                        $group->members()->attach($user);
                        Log::info("Added '{$user->getName()}' to group '{$standardGroupDN}'.");

                        // Set primary group if it's the first one
                        if ($isFirstGroup) {
                            
                            $stringSid = $group->getObjectSid();
                            $rid = last(explode('-', $stringSid));
                            
                            if (is_numeric($rid)) {
                                $user->setAttribute('primaryGroupID', $rid);
                                $user->save(); // Save the primary group change
                                Log::info("Set primary group ID to {$rid} for user '{$user->getName()}'.");
                            } else {
                                Log::warning("Could not extract RID from group SID: {$stringSid} for group '{$standardGroupDN}'");
                            }
                            
                            $isFirstGroup = false;
                        }

                    } else {
                        Log::warning("Group '{$standardGroupDN}' not found in domain '{$domain}'.");
                    }
                }                
            }

            // 4. Remove Domain Users
            $this->removeUserFromGroup($domain, $user, 'Domain Users');

            return ['user' => $user, 'initialPassword' => $initialPassword];

        } catch (\Exception $e) {
            Log::error("Failed to create admin user '{$cn}': " . $e->getMessage());
            throw $e;
        }
    }

    /**
     *  Update an existing privileged (admin) Active Directory user account.
     *
     * @param string $domain
     * @param string $samAccountName
     * @param array $data Validated data from UpdateUserRequest
     * @return LdapUser
     */
    public function updateAdminUser(string $domain, array $data): array
    {
        $baseSam = $data['badgeNumber'];
        $adminSam = "{$baseSam}-a";
        $cn = "admin-{$data['firstName']}{$data['lastName']}";

        Log::info("Updating admin account '{$adminSam}' in domain '{$domain}'");

        try {
            $adminUser = $this->findUserBySamAccountName($adminSam, $domain);
            if (!$adminUser) {
                throw new \Exception("Admin user '{$adminSam}' not found.");
            }

            $updates = [
                'displayName' => "admin-" . strtolower($data['firstName'] . $data['lastName']),
                'givenName' => $data['firstName'],
                'sn' => $data['lastName'],
                'mail' => "{$baseSam}-a@{$domain}",
                'mobile' => $data['mobileNumber'],
                'accountExpires' => Carbon::now()->addMonth()->timestamp,
            ];

            foreach ($updates as $attr => $value) {
                try {
                    $adminUser->setAttribute($attr, $value);
                } catch (\Exception $e) {
                    Log::warning("Failed updating attribute '{$attr}' for '{$adminSam}': " . $e->getMessage());
                }
            }

            $adminUser->save();

            // Update group memberships
            foreach (($data['optionalGroupsForHighPrivilegeUsers'] ?? []) as $groupName) {
                try {
                    $group = LdapGroup::on($domain)->where('samaccountname', '=', $groupName)->first();
                    if ($group) {
                        $group->members()->syncWithoutDetaching([$adminUser]);
                        Log::info("Updated group membership for '{$adminSam}' in '{$groupName}'");
                    }
                } catch (\Exception $e) {
                    Log::error("Group update failed for '{$adminSam}' in '{$groupName}': " . $e->getMessage());
                }
            }

            // --- Remove from default 'Domain Users' group using helper ---
            $this->removeUserFromGroup($domain, $adminUser, 'Domain Users');

            return ['user' => $adminUser];

        } catch (\Exception $e) {
            Log::error("Failed to update admin user '{$adminSam}': " . $e->getMessage());
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
