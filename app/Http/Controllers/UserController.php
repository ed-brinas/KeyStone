<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\Models\ActiveDirectory\Group;
use LdapRecord\Container;
use LdapRecord\Connection;
use LdapRecord\LdapRecordException;
use Illuminate\Support\Facades\Validator;
use LdapRecord\Models\Attributes\Password;
use Carbon\Carbon;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @param Request $request
     * @return \Illuminate\View\View
     */
    public function index(Request $request)
    {
        $domains = config('keystone.adSettings.domains', []);
        $selectedDomain = $request->input('domain', $domains[0] ?? null);
        $searchQuery = $request->input('search_query', '');
        $users = [];
        $error = null;

        if ($selectedDomain) {
            try {
                $this->setLdapConnection($selectedDomain);

                $searchOus = config('keystone.provisioning.searchBaseOus', []);
                $query = User::query();

                if (!empty($searchQuery)) {
                    $query->where(function ($q) use ($searchQuery) {
                        $q->where('cn', 'contains', $searchQuery)
                          ->orWhere('samaccountname', 'contains', 'like', '%' . $searchQuery . '%')
                          ->orWhere('mail', 'contains', $searchQuery);
                    });
                }

                $usersInOus = [];
                foreach ($searchOus as $ou) {
                    $domainComponents = 'dc=' . str_replace('.', ',dc=', $selectedDomain);
                    $fullOu = str_replace('{domain-components}', $domainComponents, $ou);

                    $ouQuery = clone $query;
                    $results = $ouQuery->in($fullOu)->get();
                    if ($results) {
                       $usersInOus = array_merge($usersInOus, $results->all());
                    }
                }

                $users = $usersInOus;

            } catch (LdapRecordException $e) {
                $error = "Could not connect or search in LDAP directory for domain '{$selectedDomain}'. Please check the configuration. Error: " . $e->getMessage();
            }
        } else {
            $error = "No domains configured. Please check your keystone.php configuration file.";
        }

        $provisioningOus = config('keystone.provisioning.provisioningOus', []);
        $optionalGroups = config('keystone.provisioning.optionalGroupsForStandardUser', []);
        return view('users.index', compact('users', 'domains', 'selectedDomain', 'searchQuery', 'error', 'provisioningOus', 'optionalGroups'));
    }

    /**
     * Dynamically sets the default LDAP connection.
     *
     * @param string $domain
     * @return void
     */
    private function setLdapConnection(string $domain): void
    {
        $config = config('ldap.connections.default');
        $config['base_dn'] = 'dc=' . str_replace('.', ',dc=', $domain);
        $domainAdServers = config("keystone.adSettings.domain_controllers.{$domain}");

        if (!empty($domainAdServers)) {
            $config['hosts'] = $domainAdServers;
        }

        $connection = new Connection($config);

        Container::addConnection($connection, $domain);

        Container::setDefaultConnection($domain);
    }

    /**
     * Show the form for creating a a new resource.
     */
    public function create()
    {
        $domains = config('keystone.adSettings.domains', []);
        $selectedDomain = $domains[0] ?? null;
        $optionalGroups = config('keystone.provisioning.optionalGroupsForStandardUser', []);
        return view('users.index', compact('domains', 'selectedDomain', 'optionalGroups'));
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required|string|max:50',
            'last_name' => 'required|string|max:50',
            'date_of_birth' => 'required|date',
            'mobile_number' => 'required|string|max:20',
            'domain' => 'required|string',
            'account_expires' => 'nullable|date|after:today',
            'groups' => 'nullable|array'
        ]);


        if ($validator->fails()) {
            return redirect()->back()->withErrors($validator)->withInput()->with('open_modal', '#userCreateModal');
        }


        try {
            $this->setLdapConnection($request->domain);

            $firstName = $request->first_name;
            $lastName = $request->last_name;
            $displayName = "$firstName $lastName";
            $samAccountName = strtolower(substr($firstName, 0, 1) . '.' . $lastName);

            if (User::where('samaccountname', '=', $samAccountName)->exists()) {

                return redirect()->back()->with('error', 'A user with that username already exists.')->withInput()->with('open_modal', '#userCreateModal');

            }

            $user = new User();

            $ouStandardUser = config('keystone.provisioning.ouStandardUser');
            $domainComponents = 'dc=' . str_replace('.', ',dc=', $request->domain);
            $fullOu = str_replace('{domain-components}', $domainComponents, $ouStandardUser);

            $user->setDn("cn=$displayName," . $fullOu);

            $user->givenname = $firstName;
            $user->sn = $lastName;
            $user->cn = $displayName;
            $user->displayname = $displayName;
            $user->samaccountname = $samAccountName;
            $user->userprincipalname = $samAccountName . '@' . $request->domain;

            $password = $this->generatePassword();
            $user->unicodepwd = Password::encode($password);

            $user->mobile = $request->mobile_number;
            $user->extensionattribute1 = $request->date_of_birth;

            if ($request->filled('account_expires')) {
                $user->accountexpires = Carbon::parse($request->account_expires)->endOfDay();
            } else {
                $user->accountexpires = 0; // Never expires
            }

            $user->useraccountcontrol = 512;

            $user->save();

            if ($request->has('groups')) {
                foreach ($request->groups as $groupName) {
                    $group = Group::find("cn=$groupName,ou=Groups," . $domainComponents);
                    if ($group) {
                        $user->groups()->attach($group);
                    }
                }
            }

            $user->pwdlastset = -1;
            $user->save();

            $successMessage = "User created successfully. Temporary Password: <strong>$password</strong>";
            return redirect()->route('users.index')->with('success', $successMessage);

        } catch (\Exception $e) {

            return redirect()->back()->with('error', 'Failed to create user: ' . $e->getMessage())->withInput()->with('open_modal', '#userCreateModal');

        }
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guid
     * @return \Illuminate\Http\RedirectResponse
     */
    public function update(Request $request, $guid)
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required|string|max:50',
            'last_name' => 'required|string|max:50',
            'date_of_birth' => 'required|date',
            'mobile_number' => 'required|string|max:20',
            'domain' => 'required|string',
            'account_expires' => 'nullable|date|after:today',
            'password' => 'nullable|string|min:8|confirmed',
            'groups' => 'nullable|array'
        ]);


        if ($validator->fails()) {
            return redirect()->back()->withErrors($validator)->withInput()->with('open_modal', '#editUserModal-' . $guid);
        }


        try {
            $this->setLdapConnection($request->domain);
            $user = User::findOrFail($guid);

            $user->givenname = $request->first_name;
            $user->sn = $request->last_name;
            $user->displayname = $request->first_name . ' ' . $request->last_name;

            $user->mobile = $request->mobile_number;
            $user->extensionattribute1 = $request->date_of_birth;

            if ($request->filled('account_expires')) {
                $user->accountexpires = Carbon::parse($request->account_expires)->endOfDay();
            } else {
                $user->accountexpires = 0; // Never expires
            }

            if ($request->filled('password')) {
                $user->unicodepwd = Password::encode($request->password);
            }

            $user->save();

            $domainComponents = 'dc=' . str_replace('.', ',dc=', $request->domain);
            $userGroups = $user->groups()->get()->pluck('cn')->flatten()->toArray();
            $submittedGroups = $request->input('groups', []);

            $groupsToAdd = array_diff($submittedGroups, $userGroups);
            foreach ($groupsToAdd as $groupName) {
                $group = Group::find("cn=$groupName,ou=Groups," . $domainComponents);
                if($group) $user->groups()->attach($group);
            }

            $groupsToRemove = array_diff($userGroups, $submittedGroups);
             foreach ($groupsToRemove as $groupName) {
                $group = Group::find("cn=$groupName,ou=Groups," . $domainComponents);
                if($group) $user->groups()->detach($group);
            }

            return redirect()->route('users.index')->with('success', 'User updated successfully.');
        } catch (\Exception $e) {

            return redirect()->back()->with('error', 'Failed to update user: ' . $e->getMessage())->with('open_modal', '#editUserModal-' . $guid);

        }
    }

    /**
     * Update the account status (enable/disable).
     *
     * @param string $guid
     * @param Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function toggleStatus($guid, Request $request)
    {
        try {
            $this->setLdapConnection($request->input('domain'));
            $user = User::findOrFail($guid);

            if ($user->isDisabled()) {
                $user->useraccountcontrol = 512; // Enable Account
                $message = 'User enabled successfully.';
            } else {
                $user->useraccountcontrol = 514; // Disable Account
                $message = 'User disabled successfully.';
            }
            $user->save();
            return redirect()->back()->with('success', $message);
        } catch (\Exception $e) {
            return redirect()->back()->with('error', 'Failed to update user status: ' . $e->getMessage());
        }
    }

    /**
     * Unlock the specified user account.
     *
     * @param string $guid
     * @param Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function unlock($guid, Request $request)
    {
        try {
            $this->setLdapConnection($request->input('domain'));
            $user = User::findOrFail($guid);

            $user->lockouttime = 0;
            $user->save();

            return redirect()->back()->with('success', 'User unlocked successfully.');
        } catch (\Exception $e) {
            return redirect()->back()->with('error', 'Failed to unlock user: ' . $e->getMessage());
        }
    }

    // MODIFIED START - 2025-10-10 23:08 - Changed visibility to protected and corrected password generation logic.
    /**
     * Generates a complex password (8 characters; mixed case, numbers, special characters).
     *
     * @return string
     */
    protected function generatePassword(): string
    {
        $lowercase = 'abcdefghjkmnpqrstuvwxyz';
        $uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $numbers = '23456789';
        $specialChars = '!@#$%^&*()-_+={}[]|:;<>?';

        $pool = $lowercase . $uppercase . $numbers . $specialChars;

        $password = '';

        // Ensure at least one of each required type
        $password .= $lowercase[rand(0, strlen($lowercase) - 1)];
        $password .= $uppercase[rand(0, strlen($uppercase) - 1)];
        $password .= $numbers[rand(0, strlen($numbers) - 1)];
        $password .= $specialChars[rand(0, strlen($specialChars) - 1)];

        // Fill the rest of the 8 characters randomly (Total of 8 characters)
        for ($i = 0; $i < 4; $i++) {
            $password .= $pool[rand(0, strlen($pool) - 1)];
        }

        // Shuffle the password to ensure randomness
        return str_shuffle($password);
    }
    // MODIFIED END - 2025-10-10 23:08

    // MODIFIED START - 2025-10-10 23:08 - Updated timestamp to finalize password reset logic.
    /**
     * Reset the password for a user.
     *
     * @param string $guid
     * @param Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function resetPassword($guid, Request $request)
    {
        try {
            $this->setLdapConnection($request->input('domain'));
            $user = User::findOrFail($guid);

            $newPassword = $this->generatePassword();

            // Set the new password
            $user->unicodepwd = Password::encode($newPassword);

            // Unlock the account if it's locked
            $user->lockouttime = 0;

            // Force user to change password at next logon
            $user->pwdlastset = 0;

            $user->save();

            // Flash session with success flag, username and new password
            return redirect()->route('users.index')
                ->with('reset_success', true)
                ->with('reset_username', $user->getFirstAttribute('samaccountname'))
                ->with('reset_password', $newPassword);

        } catch (\Exception $e) {
            return redirect()->back()->with('error', 'Failed to reset password: ' . $e->getMessage());
        }
    }
    // MODIFIED END - 2025-10-10 23:08
}
