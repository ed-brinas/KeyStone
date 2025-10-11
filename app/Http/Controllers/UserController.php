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
// MODIFIED START - 2025-10-11 08:59 - Added Log facade for password reset logging.
use Illuminate\Support\Facades\Log;
// MODIFIED END

class UserController extends Controller
{

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
     * Reset a user's password and unlock the account if locked.
     *
     * This function:
     * 1. Locates the user by ID.
     * 2. Generates a new random secure password.
     * 3. Calls the Active Directory (or internal) service to reset and unlock the account.
     * 4. Logs the action for auditing.
     * 5. Returns the new password to the frontend for display.
     */
    public function resetPassword($id)
    {
        // Retrieve the target user record by ID
        $user = User::findOrFail($id);

        // Generate a new secure password (8+ chars, mixed complexity)
        $newPassword = Str::random(10) . '!';

        // Perform the AD password reset and unlock operation
        // The adService handles connection and LDAP/AD interactions.
        $success = $this->adService->resetAndUnlockAccount($user->username, $newPassword);

        // If the reset succeeds, record the event and return the new password
        if ($success) {
            AuditLog::create([
                'admin'        => auth()->user()->username, // Administrator performing the reset
                'action'       => 'Reset Password',          // Action type
                'target_user'  => $user->username,           // Affected account
                'status'       => 'Success',                 // Outcome
                'ip_address'   => request()->ip()            // Source IP for traceability
            ]);

            // Return the newly generated password to the frontend
            return response()->json(['new_password' => $newPassword]);
        }

        // On failure, return a 500 error response
        return response()->json(['error' => 'Failed to reset password'], 500);
    }

}
