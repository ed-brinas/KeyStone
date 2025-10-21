<?php

namespace App\Services;

use App\Models\User as LocalUser;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use LdapRecord\Container;
use LdapRecord\Models\ActiveDirectory\User as AdUser;
use LdapRecord\Models\ModelNotFoundException;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class AdService
{
    /**
     * Set the LdapRecord connection for the given domain.
     */
    protected function setDomainConnection(string $domain): void
    {
        $connectionName = str_replace('.', '_', $domain);
        Container::setDefault($connectionName);
    }

    /**
     * Get the Domain Component string (e.g., 'dc=ncc,dc=local') for a domain.
     */
    protected function getDomainComponents(string $domain): string
    {
        return 'dc=' . str_replace('.', ',dc=', $domain);
    }

    /**
     * Replace the {domain-components} placeholder in a given string.
     */
    protected function replaceDnPlaceholders(string $dn, string $domain): string
    {
        return str_replace('{domain-components}', $this->getDomainComponents($domain), $dn);
    }

    /**
     * Authenticate a user against a specific domain.
     */
    public function authenticate(string $username, string $password): bool
    {
        $connection = Container::getDefaultConnection();
        return $connection->auth()->attempt($username, $password);
    }

    /**
     * Find an AD user by their SAMAccountName.
     */
    public function findUserByUsername(string $username): ?AdUser
    {
        try {
            return AdUser::where('samaccountname', '=', $username)->firstOrFail();
        } catch (ModelNotFoundException $e) {
            return null;
        }
    }

    /**
     * Check if a user is in any of the required groups for login.
     */
    public function isUserAuthorizedToLogin(AdUser $user): bool
    {
        $domain = strtolower(Container::getDefaultConnection()->getDomain());
        $accessGroups = Config::get('keystone.applicationAccessControl.generalAccessGroups', []);

        foreach ($accessGroups as $groupDn) {
            $formattedGroupDn = $this->replaceDnPlaceholders($groupDn, $domain);
            if ($user->groups()->exists($formattedGroupDn)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sync local roles and permissions based on the user's AD group membership.
     */
    public function syncUserRolesAndPermissions(LocalUser $localUser, AdUser $adUser): void
    {
        $domain = strtolower(Container::getDefaultConnection()->getDomain());
        $permissionMap = Config::get('keystone.permissionMap', []);
        $permissionsToAssign = ['access-api']; // Base permission

        foreach ($permissionMap as $groupDn => $permissions) {
            $formattedGroupDn = $this->replaceDnPlaceholders($groupDn, $domain);
            if ($adUser->groups()->exists($formattedGroupDn)) {
                $permissionsToAssign = array_merge($permissionsToAssign, $permissions);
            }
        }
        
        $localUser->syncPermissions(array_unique($permissionsToAssign));
    }

    /**
     * Create a new Active Directory user.
     */
    public function createUser(array $data): AdUser
    {
        $this->setDomainConnection($data['domain']);
        
        $ou = Config::get('keystone.provisioning.ouStandardUser');
        $ou = $this->replaceDnPlaceholders($ou, $data['domain']);

        $user = new AdUser();
        $user->setDn('cn=' . $data['displayName'] . ',' . $ou);
        
        $user->samaccountname = $data['username'];
        $user->displayname = $data['displayName'];
        $user->givenname = $data['firstName'];
        $user->sn = $data['lastName'];
        $user->userprincipalname = $data['username'] . '@' . $data['domain'];
        
        $user->save();

        // Enable account (it's created disabled by default)
        $user->useraccountcontrol = 512; // Normal Account
        $user->save();

        return $user;
    }

    /**
     * Reset a user's password.
     */
    public function resetPassword(AdUser $user, string $password): void
    {
        $user->unicodePwd = $password;
        // Require password change at next logon
        $user->pwdlastset = 0;
        $user->save();
    }
    
    /**
     * Enable a user account.
     */
    public function enableAccount(AdUser $user): void
    {
        $user->useraccountcontrol = 512; // Normal Account
        $user->save();
    }

    /**
     * Disable a user account.
     */
    public function disableAccount(AdUser $user): void
    {
        $user->useraccountcontrol = 514; // Account Disabled
        $user->save();
    }

    /**
     * Unlock a user account.
     */
    public function unlockAccount(AdUser $user): void
    {
        $user->lockouttime = 0;
        $user->save();
    }

    /**
     * Generate a strong, random password.
     */
    public function generatePassword(): string
    {
        return Str::random(16) . 'aA1!';
    }
}
