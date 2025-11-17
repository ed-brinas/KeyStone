<?php

namespace App\Services;

use Carbon\Carbon;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use LdapRecord\Models\ActiveDirectory\User as LdapUser;
use LdapRecord\Models\ActiveDirectory\Group as LdapGroup;
use LdapRecord\Models\Attributes\Sid as LdapSid;
use LdapRecord\Models\ModelNotFoundException;
use LdapRecord\LdapRecordException;
use LdapRecord\Container;
use LdapRecord\Connection;

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
                $group->members()->attach($user);
                Log::info("Attached '{$user->getName()}' to group '{$groupName}'. (If not already a member).");
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

                $group->members()->detach($user);
                Log::info("Detached '{$user->getName()}' from group '{$groupName}'. (If they were a member).");
                return true;
                 
            }
            Log::warning("Group '{$groupName}' not found in domain '{$domain}'.");
        } catch (\Exception $e) {
            Log::error("Failed to remove '{$user->getName()}' from group '{$groupName}': " . $e->getMessage());
        }
        return false;
    }


    /**
     * Synchronizes a user's group memberships based on a submitted list.
     *
     * @param string $domain
     * @param LdapUser $user
     * @param array $submittedGroupDns The complete list of group DNs the user *should* be in.
     * @param bool $isAdmin Indicates if this sync is for an admin account.
     * @return void
     */
    protected function syncUserGroups(string $domain, LdapUser $user, array $submittedGroupDns, bool $isAdmin = false): void
    {
        Log::info("Starting group sync for '{$user->getName()}' in domain '{$domain}'. IsAdmin: " . ($isAdmin ? 'Yes' : 'No'));
        try {

            // --- START: MODIFICATION - Implement user's requested sequence for Admins ---
            if ($isAdmin) {
                // --- ADMIN-SPECIFIC SYNC LOGIC ---
                // This implements the user's requested sequence to prevent race conditions
                // when removing the 'Domain Users' group.

                // 1. Set the selected group as the primary group.
                if (!empty($submittedGroupDns)) {
                    $primaryGroupDn = $submittedGroupDns[0];
                    Log::info("SyncUserGroups [Admin]: STEP 1 - Setting primary group to '{$primaryGroupDn}'.");
                    $this->setAsPrimaryGroup($domain, $user, $primaryGroupDn);
                } else {
                    Log::warning("SyncUserGroups [Admin]: STEP 1 - No groups submitted for '{$user->getName()}'. Cannot set a primary group.");
                }

                // 2. Wait for recommended seconds for AD replication.
                // Note: Using sleep() in a web request is generally bad practice as it blocks
                // the thread. A better long-term solution would be a queued job.
                $delay = 5; // 5 seconds recommended delay
                Log::info("SyncUserGroups [Admin]: STEP 2 - Waiting {$delay} seconds for AD replication...");
                sleep($delay);

                // 3. Perform the full group sync (add/remove).
                // 'Domain Users' will be removed here if it's not in the submitted list.
                Log::info("SyncUserGroups [Admin]: STEP 3 - Performing full group membership sync.");

                $currentGroupDns = $user->groups()->get()
                    ->pluck('distinguishedname')
                    ->flatten()
                    ->filter(fn($g) => is_string($g) && !empty($g))
                    ->unique();
                $currentGroupDnsLower = $currentGroupDns->map('strtolower')->toArray();
                $submittedGroupDnsLower = array_map('strtolower', $submittedGroupDns);

                // Add Groups
                $groupsToAddLower = array_diff($submittedGroupDnsLower, $currentGroupDnsLower);
                $groupsToAdd = collect($submittedGroupDns)->filter(function ($dn) use ($groupsToAddLower) {
                    return in_array(strtolower($dn), $groupsToAddLower);
                })->all();

                foreach ($groupsToAdd as $groupDn) {
                    Log::info("SyncUserGroups [Admin]: Adding user to group '{$groupDn}'.");
                    $this->addUserToGroup($domain, $user, $groupDn);
                }

                // Remove Groups
                $groupsToRemoveLower = array_diff($currentGroupDnsLower, $submittedGroupDnsLower);
                $groupsToRemove = $currentGroupDns->filter(function ($dn) use ($groupsToRemoveLower) {
                    return in_array(strtolower($dn), $groupsToRemoveLower);
                })->all();
                
                // For admins, we do NOT filter 'Domain Users'.
                // If 'Domain Users' is not in $submittedGroupDns,
                // it will be in $groupsToRemove, and it will be removed.
                // This satisfies the user's Step 3.
                foreach ($groupsToRemove as $groupDn) {
                    Log::info("SyncUserGroups [Admin]: Removing user from group '{$groupDn}'.");
                    $this->removeUserFromGroup($domain, $user, $groupDn);
                }
                
                Log::info("SyncUserGroups [Admin]: Sync complete.");

            } else {
                // --- REGULAR USER SYNC LOGIC (Unchanged from original) ---
                Log::info("SyncUserGroups [Regular]: Using standard sync logic.");

                // b.1. Retrieve the user's complete list of current groups.
                $currentGroupDns = $user->groups()->get()
                    ->pluck('distinguishedname')
                    ->flatten()
                    ->filter(fn($g) => is_string($g) && !empty($g))
                    ->unique(); 

                $currentGroupDnsLower = $currentGroupDns->map('strtolower')->toArray();
                $submittedGroupDnsLower = array_map('strtolower', $submittedGroupDns);

                // b.4. Find groups to add:
                $groupsToAddLower = array_diff($submittedGroupDnsLower, $currentGroupDnsLower);
                $groupsToAdd = collect($submittedGroupDns)->filter(function ($dn) use ($groupsToAddLower) {
                    return in_array(strtolower($dn), $groupsToAddLower);
                })->all();

                foreach ($groupsToAdd as $groupDn) {
                    Log::info("SyncUserGroups [Regular]: Adding user to group '{$groupDn}'.");
                    $this->addUserToGroup($domain, $user, $groupDn);
                }

                // b.3. Find groups to remove:
                $groupsToRemoveLower = array_diff($currentGroupDnsLower, $submittedGroupDnsLower);
                $groupsToRemove = $currentGroupDns->filter(function ($dn) use ($groupsToRemoveLower) {
                    return in_array(strtolower($dn), $groupsToRemoveLower);
                });

                // This is a Regular User. We must NOT remove "Domain Users".
                $domainUsersDnLower = 'cn=domain users,cn=users,dc=ncc,dc=lab';
                $groupsToRemove = $groupsToRemove->filter(function ($dn) use ($domainUsersDnLower) {
                    // Keep the group in the removal list ONLY if its lowercase DN is NOT "domain users"
                    return strtolower($dn) !== $domainUsersDnLower;
                });
                Log::info("SyncUserGroups [Regular]: Filtered 'Domain Users' from removal list.");

                $groupsToRemove = $groupsToRemove->all();

                foreach ($groupsToRemove as $groupDn) {
                    Log::info("SyncUserGroups [Regular]: Removing user from group '{$groupDn}'.");
                    $this->removeUserFromGroup($domain, $user, $groupDn);
                }

                // b.5. Designate one of the final groups as the user's primary group.
                if (!empty($submittedGroupDns)) {
                    $primaryGroupDn = $submittedGroupDns[0];
                    Log::info("SyncUserGroups [Regular]: Setting primary group to '{$primaryGroupDn}'.");
                    $this->setAsPrimaryGroup($domain, $user, $primaryGroupDn);
                } else {
                    Log::warning("SyncUserGroups [Regular]: No groups submitted for '{$user->getName()}'. Cannot set a primary group.");
                }
            }
            // --- END: MODIFICATION ---

        } catch (\Exception $e) {
            Log::error("Failed to sync groups for '{$user->getName()}': " . $e->getMessage());
        }
    }

    /**
     * Sets the primary group for an Active Directory user.
     *
     * @param string $userSamAccountName The sAMAccountName of the user (e.g., 'john.doe').
     * @param string $targetGroupDn The Distinguished Name of the target group (e.g., 'CN=L1,CN=Users,DC=ncc,DC=local').
     * @return bool True on success, false on failure.
     */
    protected function setAsPrimaryGroup(string $domain, LdapUser $user, string $targetGroupDn): bool
    {
        try {
            // 1. Find the Group
            // Explicitly select 'primaryGroupToken' as it's a constructed attribute
            // and may not be loaded by default.
            $group = LdapGroup::on($domain)
                        ->select('*', 'primaryGroupToken')
                        ->where('distinguishedname', '=', $targetGroupDn)
                        ->first();

            if (!$group) {
                Log::warning("setAsPrimaryGroup: Group '{$targetGroupDn}' not found in domain '{$domain}'.");
                return false;
            }

            // 2. --- IMPORTANT PREREQUISITE ---
            // The user MUST be a member of the new primary group BEFORE setting it.
            // We use the same logic as addUserToGroup to be safe.
            if (!$user->groups()->exists($group)) {
                Log::info("setAsPrimaryGroup: User '{$user->getName()}' is not a member of '{$targetGroupDn}'. Attaching via group model.");
                $group->members()->attach($user);
            }

            // 3. Reload the group object explicitly with the 'primaryGroupToken'
            // to ensure it is fetched, as it is a constructed attribute.            
            $primaryGroupToken = $group->getFirstAttribute('primaryGroupToken');

            if (!$primaryGroupToken) {
                Log::error("setAsPrimaryGroup: Could not retrieve primaryGroupToken for '{$targetGroupDn}'.");
                return false;
            }

            // 4. Set the User's primaryGroupID
            $user->primaryGroupID = $primaryGroupToken;

            // 5. Save the user object to commit the change to Active Directory
            $user->save();
            Log::info("Successfully set primary group for '{$user->getName()}' to '{$targetGroupDn}'.");
            return true;

        } catch (LdapRecordException $e) {
            Log::error("Active Directory Primary Group Update Failed '{$user->getName()}': " . $e->getMessage());
            return false;
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
        Log::info('User provisioning data:', array_merge($data, ['isAdmin' => $isAdmin]));

        $domain     = $data['domain'];
        $firstName  = Str::title($data['first_name']);
        $lastName   = Str::title($data['last_name']);

        // --- Conditional Attributes ---
        if ($isAdmin) {
            $cn       = "admin-".strtolower($data['first_name'].$data['last_name']);
            $sam      = $data['badge_number'].'-a';
            $dn       = $this->buildDn($cn, $domain, true);
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
            // --- MODIFICATION: We now build a list and call syncUserGroups ---
            $submittedGroups = []; 
            if ($isAdmin) {

                // --- Admin Group Logic ---
                $submittedGroups = $data['groups_privilege_user'] ?? [];
                
                // Add to default privilege group from config
                try {
                    $groupTemplate = config('keystone.provisioning.ouPrivilegeUserGroup');
                    if ($groupTemplate) {
                        $submittedGroups[] = $groupTemplate; // Add to list for sync
                        Log::info("Adding default privilege group to sync list: {$groupTemplate}");
                    } else {
                        Log::warning("keystone.provisioning.ouPrivilegeUserGroup is not defined in config.");
                    }
                } catch (\Exception $e) {
                    Log::error("Failed to add default privilege group to sync list: " . $e->getMessage());
                }

            } else {
                // --- Standard Group Logic ---
                $submittedGroups = $data['groups_standard_user'] ?? [];
            }

            // --- NEW: Resolve DNs and call syncUserGroups ---
            // This is the same logic from updateAdUser, now applied to new users.
            $resolvedGroupDns = [];
            if (is_array($submittedGroups) && !empty($submittedGroups)) {
                foreach ($submittedGroups as $group) {
                    if(is_string($group) && !empty($group)) {
                        $resolvedGroupDns[] = $this->resolveDnTemplate($group, $domain);
                    }
                }
            }
            $resolvedGroupDns = array_values(array_unique($resolvedGroupDns));

            Log::info("Calling syncUserGroups for new user '{$user->getName()}' with " . count($resolvedGroupDns) . " groups.");
            $this->syncUserGroups($domain, $user, $resolvedGroupDns, $isAdmin);
            // --- END OF NEW SECTION ---

            if ($isAdmin) {
                Log::info("Removing user must change password at next logon for ".$sam);
                $admin = LdapUser::where('samaccountname', '=', $sam)->firstOrFail();
                $admin->pwdlastset = -1;
                $admin->save();
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
        // 3. Sync all groups
        $submittedGroups = [];
        if ($isAdmin) {
            // --- Admin Group Logic ---
            $submittedGroups = $data['groups_privilege_user'] ?? [];
            
            // Add default privilege group from config
            try {
                $groupTemplate = config('keystone.provisioning.ouPrivilegeUserGroup');
                if ($groupTemplate) {
                    // We add the *template* string, as it will be resolved next.
                    $submittedGroups[] = $groupTemplate;
                    Log::info("Ensuring admin user is in default privilege group: {$groupTemplate}");
                } else {
                    Log::warning("keystone.provisioning.ouPrivilegeUserGroup is not defined in config.");
                }
            } catch (\Exception $e) {
                Log::error("Failed to add default privilege group to sync list: " . $e->getMessage());
            }

        } else {
            // --- Standard Group Logic ---
            $submittedGroups = $data['groups_standard_user'] ?? [];
        }

        // Resolve all template DNs
        $resolvedGroupDns = [];
        if (is_array($submittedGroups) && !empty($submittedGroups)) {
            foreach ($submittedGroups as $group) {
                // Ensure group is a string before resolving
                if(is_string($group) && !empty($group)) {
                    $resolvedGroupDns[] = $this->resolveDnTemplate($group, $domain);
                }
            }
        }
        
        // Remove duplicates just in case
        $resolvedGroupDns = array_values(array_unique($resolvedGroupDns));

        Log::info("Calling syncUserGroups for '{$user->getName()}' with " . count($resolvedGroupDns) . " groups.");

        // Pass the $isAdmin flag to syncUserGroups
        $this->syncUserGroups($domain, $user, $resolvedGroupDns, $isAdmin);

        return $user;
    }

      /**
     * Checks the status of an Active Directory account, returning true if it is enabled.
     *
     * @param string $domain The LDAP connection name (domain) to search on.
     * @param string $samAccountName The sAMAccountName of the user.
     * @return bool True if the account is found and is enabled (not disabled or locked), false otherwise.
     */
    protected function checkAccountStatus(string $domain, string $samAccountName): bool
    {
        Log::info("Checking AD account status for '{$samAccountName}' on domain '{$domain}'.");

        // Use LdapUser to search for the user by sAMAccountName on the specified connection ($domain)
        $user = LdapUser::on($domain)
            ->where('samaccountname', '=', $samAccountName)
            ->first();

        // Account not found, disabled, or locked out means the status check fails (returns false).
        if (!$user) {
            Log::warning("Account '{$samAccountName}' not found.");
            return false;
        }

        if ($user->isDisabled()) {
            Log::warning("Account '{$samAccountName}' is disabled.");
            return false;
        }

        if ((int) $user->getAttribute('lockouttime') > 0) {
            Log::warning("Account '{$samAccountName}' is locked out (lockouttime > 0).");
            return false;
        }

        // If the account is found, not disabled, and not locked, it is enabled.
        Log::info("Account '{$samAccountName}' is enabled.");
        return true;
    }  

    /**
     * Checks if an Active Directory account exists based on its sAMAccountName.
     *
     * @param string $domain The LDAP connection name (domain) to search on.
     * @param string $samAccountName The sAMAccountName of the user.
     * @return bool True if the account is found, false otherwise.
     */
    public function checkAccountExists(string $domain, string $samAccountName): bool
    {
        Log::info("Checking if AD account '{$samAccountName}' exists on domain '{$domain}'.");

        $user = LdapUser::on($domain)
            ->where('samaccountname', '=', $samAccountName)
            ->first();

        $exists = $user !== null;

        if ($exists) {
            Log::info("Account '{$samAccountName}' exists.");
        } else {
            Log::info("Account '{$samAccountName}' does not exist.");
        }

        return $exists;
    }

    // ===================================================================
    // PUBLIC METHODS
    // ===================================================================

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
        $special = '!@#$=';

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

            // 2. Unlock Account (logic from unlockAccount)
            $user->setAttribute('lockouttime', 0);

            // 3. Enable Account (logic from enableAccount)
            $currentValue = (int)$user->getFirstAttribute('useraccountcontrol');
            $accountDisableFlag = 2; // ACCOUNTDISABLE flag

            // Check if the account is currently disabled
            if ($currentValue & $accountDisableFlag) {
                // To enable, we use a bitwise AND with the INVERSE of the flag
                $user->useraccountcontrol = $currentValue & ~$accountDisableFlag;
            }

            // 4. Save all changes         
            try {
                $user->save();
                Log::info("Password reset, unlocked, and enabled user: {$user->getFirstAttribute('samaccountname')}");
            } catch (\Exception $e) {
                Log::error("Failed to Password reset, unlocked, and enabled user: {$user->getFirstAttribute('samaccountname')} " . $e->getMessage());
            }

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

            $user = $this->findUserBySamAccountName($samToUpdate, $domain);

            if (!$user) {
                throw new ModelNotFoundException("User '{$samToUpdate}' not found in domain '{$domain}'.");
            }

            // --- Update Standard User Attributes (call protected method) ---
            $user = $this->updateAdUser($user, $data, false);
            Log::info("User '{$samToUpdate}' updated successfully.");


            // --- Admin Account Logic (Orchestration) ---
            $adminResult = null;
            $isPrivileged = !empty($data['has_admin']);
            $canManageAdmin = !empty($data['hasHighPrivilegeAccess']);

            if ($isPrivileged && $canManageAdmin) {

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

                 $adminSam = "{$samToUpdate}-a";
                 Log::info("has_admin is false. Checking if admin account '{$adminSam}' exists to delete it."); // MODIFIED LOG
                 if ($this->findUserBySamAccountName($adminSam, $domain)) {
                    $this->deleteAccount($domain, $adminSam); // MODIFIED METHOD CALL
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
     * @param LdapUser $user The admin user LdapUser object
     * @param array $data Validated data from UpdateUserRequest
     * @return LdapUser
     */
    public function updateAdminUser(LdapUser $user, array $data): array
    {
        $originalAdminSam = $user->samaccountname[0];
        Log::info("Updating admin account '{$originalAdminSam}' in domain '{$data['domain']}' via protected method.");

        try {

            $user = $this->updateAdUser($user, $data, true);

            return ['user' => $user];

        } catch (\Exception $e) {
            Log::error("Failed to update admin user '{$originalAdminSam}': " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Delete a account.
     *
     * @param string $domain
     * @param string $samAccountName
     * @return void
     */
    public function deleteAccount(string $domain, string $samAccountName): void
    {
        Log::info("Deleting account '{$samAccountName}' in domain '{$domain}'.");

        $user = $this->findUserBySamAccountName($samAccountName, $domain);

        if ($user) {
            try {
                $user->delete();
                Log::info("Account '{$samAccountName}' deleted successfully.");
            } catch (\Exception $e) {
                Log::error("Failed to delete account '{$samAccountName}': " . $e->getMessage());
                throw $e;
            }
        } else {
            Log::warning("Could not delete account '{$samAccountName}', user not found.");
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
            'domain'            => $domain,
            'badgeNumber'       => $user->getFirstAttribute('samaccountname'),
            'displayName'       => $user->getFirstAttribute('displayname'),
            'samAccountName'    => $user->getFirstAttribute('userprincipalname'),
            'firstName'         => $user->getFirstAttribute('givenname'),
            'lastName'          => $user->getFirstAttribute('sn'),
            'dateOfBirth'       => $user->getFirstAttribute('info') ?? null,
            'dateOfExpiration'  => Carbon::parse($user->getFirstAttribute('accountexpires'))->format('Y-m-d'),
            'emailAddress'      => $user->getFirstAttribute('mail') ?? null,
            'mobileNumber'      => $user->getFirstAttribute('mobile') ?? null,
            'isEnabled'         => $user->isEnabled(),
            'isLockedOut'       => ($user->getFirstAttribute('lockouttime') > 0) ? true : false,
            'memberOf'          => array_map('strtolower',$this->getUserGroups($domain,$user->getFirstAttribute('samaccountname'))),
            'hasAdminAccount'   => ($this->findUserBySamAccountName($samAccountName.'-a', $domain)) ? true : false,
            'memberOfAdmin'     => array_map('strtolower',$this->getUserGroups($domain,$user->getFirstAttribute('samaccountname').'-a')),
        ];
    }

    /**
     * Retrieves all Active Directory groups that a specific user is a member of.
     *
     * @param string $domain The LDAP connection name (domain) to search on.
     * @param string $samAccountName The sAMAccountName of the user.
     * @return array An array of group Common Names (CNs). Returns an empty array if the user is not found.
     */
    public function getUserGroups(string $domain, string $samAccountName): array
    {
        Log::info("Retrieving groups for AD account '{$samAccountName}' on domain '{$domain}'.");

        // 1. Find the user
        $user = LdapUser::on($domain)
            ->where('samaccountname', '=', $samAccountName)
            ->first();

        if (!$user) {
            Log::warning("User '{$samAccountName}' not found. Cannot retrieve groups.");
            return [];
        }

        // 2. Get the user's groups via the LdapRecord relationship
        // We retrieve the groups and select only the common name ('cn').
        $ldapGroups = $user->groups()->get(['cn']);

        // 3. Map the LdapRecord collection to an array of group names (CNs)
        $groups = $ldapGroups->map(fn (LdapGroup $group) => $group->getDn())
                             ->toArray();

        Log::info("Found " . count($groups) . " groups for user '{$samAccountName}'.");

        return $groups;
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

            Log::info('Extracting data from: '.$formattedOu);

            $query = LdapUser::in($formattedOu);
            
            if ($nameFilter) {
                $query->where('anr', '=', $nameFilter);
            }
            
            $extractedInfo = $query->get()->map(function ($ldapUser) use ($domainFilter) {

                preg_match_all('/DC=([^,]+)/i', $ldapUser->getDn(), $matches);
                $domain = implode('.', $matches[1] ?? []);

                return [
                    'domain'            => $domain,
                    'badgeNumber'       => $ldapUser->getFirstAttribute('samaccountname'),
                    'displayName'       => $ldapUser->getName(),
                    'samAccountName'    => $ldapUser->getFirstAttribute('userprincipalname'),
                    'dateOfExpiration'  => $this->convertDateToTimestamp($ldapUser->getFirstAttribute('accountexpires')),
                    'isEnabled'         => $ldapUser->isEnabled(),
                    'hasAdminAccount'   => ($this->findUserBySamAccountName($ldapUser->getFirstAttribute('samaccountname').'-a', $domain)) ? true : false,
                    'isEnabledAdmin'    => $this->checkAccountStatus($domain,$ldapUser->getFirstAttribute('samaccountname').'-a'),
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
     * Unlock a user account.
     *
     * @param string $domain
     * @param string $samAccountName
     * @return void
     */
    public function unlockAccount(string $domain, string $samAccountName): void
    {
        $user = $this->findUserBySamAccountName($samAccountName, $domain);

        $isLocked = $user->getFirstAttribute('lockouttime') > 0;

        if (!$isLocked) {
            Log::info("Account '{$samAccountName}' on domain '{$domain}' is not locked. No action needed.");
            return; // No need to proceed if the account isn't locked
        }
        
        try {
            $user->update(['lockouttime' => 0]); 
            Log::info("Disabled account for '{$samAccountName}'.");
        } catch (\Exception $e) {
            Log::error("Failed to save user '{$samAccountName}' after disabling account: " . $e->getMessage());
        }           
        Log::info("Successfully initiated unlock for account '{$user->getDn()}'.");      
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

        // We get the current value
        $currentValue = (int)$user->getFirstAttribute('useraccountcontrol');

        // Define the 'ACCOUNTDISABLE' flag (value of 2)
        $accountDisableFlag = 2;

        // Check if the flag is NOT set (i.e., if the account is currently enabled)
        if (!($currentValue & $accountDisableFlag)) {

            // To disable, we use a bitwise OR to ADD the flag
            // This adds '2' to the value (e.g., 512 becomes 514)
            $user->useraccountcontrol = $currentValue | $accountDisableFlag;

            // We trust the save() operation, same as the unlockAccount fix
            try {
                $user->save();
                Log::info("Disabled account for '{$samAccountName}'.");
            } catch (\Exception $e) {
                Log::error("Failed to save user '{$samAccountName}' after disabling account: " . $e->getMessage());
            }

        } else {
            Log::info("Account '{$samAccountName}' is already disabled.");
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

        // We get the current value
        $currentValue = (int)$user->getFirstAttribute('useraccountcontrol');
        
        // Define the 'ACCOUNTDISABLE' flag
        $accountDisableFlag = 2;

        // Check if the flag is actually set (i.e., if the account is disabled)
        if ($currentValue & $accountDisableFlag) {
            
            // To enable, we use a bitwise AND with the INVERSE of the flag
            // This removes the '2' from the value (e.g., 514 becomes 512)
            $user->useraccountcontrol = $currentValue & ~$accountDisableFlag;
            
            // We trust the save() operation, same as the unlockAccount fix
            try {
                $user->save();
                Log::info("Account successfully Enabled for '{$samAccountName}'.");
            } catch (\Exception $e) {
                Log::error("Failed to save user '{$samAccountName}' after enabling account: " . $e->getMessage());
            }

        } else {
            Log::info("Account '{$samAccountName}' is already enabled.");
        }
    }

    /**
     * Set a user's account expiration date to 30 days from now.
     *
     * @param string $domain
     * @param string $samAccountName
     * @return void
     * @throws ModelNotFoundException
     * @throws \Exception
     */
    public function setExpiration(string $domain, string $samAccountName, int $days): void
    {
        Log::info("Attempting to set expiration for '{$samAccountName}' on domain '{$domain}'.");

        $user = $this->findUserBySamAccountName($samAccountName, $domain);
        
        if (!$user) {
            throw new ModelNotFoundException("User '{$samAccountName}' not found.");
        }

        try {
            // Set expiration to 30 days from now.
            $expiresDate = $this->convertDateToAdTimestamp(Carbon::now()->addDays($days)->toDateString());
            $user->accountExpires = $expiresDate;
            
            $user->save();
            
            Log::info("Successfully set account '{$samAccountName}' to expire on {$expiresDate}.");
        
        } catch (\Exception $e) {
            Log::error("Failed to set expiration for user '{$samAccountName}': " . $e->getMessage());
            throw new \Exception("Failed to set expiration: " . $e->getMessage());
        }
    }
}