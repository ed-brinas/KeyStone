<?php

namespace App\Services;

use LdapRecord\Container;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\Models\ActiveDirectory\Group;

class ActiveDirectoryService
{
    protected function provider()
    {
        return Container::getConnection('default');
    }

    public function bindAsUser(string $sam, string $password): bool
    {
        $fqUser = $sam.'@'.config('adsettings.domain');
        try {
            return $this->provider()->auth()->attempt($fqUser, $password, $bindAsUser = true);
        } catch (\Throwable $e) {
            return false;
        }
    }

    public function findBySam(string $sam): ?User
    {
        return User::query()->whereEquals('samaccountname', $sam)->first();
    }

    public function searchUsers(string $q = '')
    {
        $query = User::query();
        foreach (config('adsettings.searchBases') as $base) {
            $query->in($base);
        }
        if ($q) {
            $query->whereContains('cn', $q)->orWhereEquals('samaccountname', $q);
        }
        return $query->get();
    }

    public function setPassword(string $dn, string $newPassword): void
    {
        $user = User::find($dn);
        $user->setPassword($newPassword); // LdapRecord handles unicodePwd via LDAPS/StartTLS
        $user->save();
    }

    public function unlock(string $dn): void
    {
        $user = User::find($dn);
        $user->unlock();
        $user->save();
    }

    public function enableDisable(string $dn, bool $enable): void
    {
        $user = User::find($dn);
        $enable ? $user->enable() : $user->disable();
        $user->save();
    }

    public function createStandard(array $attrs): string
    {
        // Minimal example; fill with your exact attribute policy (name casing, UPN, etc.)
        $ou = config('adsettings.ouStandard');
        $user = (new User)->inside($ou);
        $user->cn            = $attrs['cn'];
        $user->samaccountname= $attrs['sam'];
        $user->userprincipalname = $attrs['sam'].'@'.config('adsettings.domain');
        $user->givenname     = $attrs['givenName'] ?? null;
        $user->sn            = $attrs['sn'] ?? null;
        $user->displayname   = $attrs['displayName'] ?? null;
        $user->save();

        // Add to standard groups
        foreach (config('adsettings.standardGroups') as $groupDn) {
            if ($group = Group::find($groupDn)) {
                $group->members()->attach($user);
            }
        }
        return $user->getDn();
    }

    public function createAdminTwin(string $baseSam): string
    {
        $ou = config('adsettings.ouPrivilege');
        $sam = $baseSam . config('adsettings.privAdminSuffix');

        $src = $this->findBySam($baseSam);
        $user = (new User)->inside($ou);
        $user->cn = $src ? $src->getFirstAttribute('cn').config('adsettings.privAdminSuffix') : $sam;
        $user->samaccountname = $sam;
        $user->userprincipalname = $sam.'@'.config('adsettings.domain');
        if ($src) {
            $user->givenname   = $src->getFirstAttribute('givenname');
            $user->sn          = $src->getFirstAttribute('sn');
            $user->displayname = $src->getFirstAttribute('displayname') . ' (Admin)';
        }
        $user->save();

        // Attach privileged groups (and ensure Domain Users is not primary)
        foreach (config('adsettings.privilegedGroups') as $groupDn) {
            if ($group = Group::find($groupDn)) {
                $group->members()->attach($user);
            }
        }

        // Mark creation date for lifecycle sweeps (e.g., extensionAttribute1)
        $user->setAttribute('extensionAttribute1', now()->toDateString());
        $user->save();

        return $user->getDn();
    }
}
