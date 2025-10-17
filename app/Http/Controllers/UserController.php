<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use LdapRecord\Container;
use LdapRecord\Connection;
use LdapRecord\LdapRecordException;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\Models\ActiveDirectory\Group;
use LdapRecord\Models\Attributes\Password;
use Illuminate\Support\Str;


class UserController extends Controller
{
    /**
    * @OA\Get(
    * path="/api/config",
    * summary="Get configuration details",
    * description="Provides domain and optional group configuration details used for user management.",
    * tags={"Users"},
    * @OA\Response(response=200, description="Configuration retrieved successfully")
    * )
    */
    public function getConfig()
    {
        // Use the new keystone.php configuration keys
        return response()->json([
            'domains' => config('keystone.adSettings.domains', []),
            'optionalGroupsForStandard' => config('keystone.provisioning.optionalGroupsForStandardUser', []),
            'optionalGroupsForHighPrivilege' => config('keystone.provisioning.optionalGroupsForHighPrivilegeUsers', []),
        ]);
    }

    /**
    * @OA\Get(
    * path="/api/current-user",
    * summary="Get current authenticated user",
    * description="Returns details of the currently authenticated user (placeholder implementation).",
    * tags={"Users"},
    * @OA\Response(response=200, description="Authenticated user details returned successfully")
    * )
    */
    public function getCurrentUser()
    {
        // Placeholder: In a real app, get this from auth()->user()
        // TODO: Implement actual authentication and authorization check
        return response()->json([
            'name' => 'Admin User', // Example user
            'isHighPrivilege' => true, // Example privilege
        ]);
    }

    /**
    * @OA\Get(
    * path="/api/users",
    * summary="List Active Directory users",
    * description="Retrieves users filtered by domain, name, account status, and admin account existence.",
    * tags={"Users"},
    * @OA\Parameter(name="domain", in="query", required=true, @OA\Schema(type="string")),
    * @OA\Parameter(name="nameFilter", in="query", required=false, @OA\Schema(type="string")),
    * @OA\Parameter(name="statusFilter", in="query", required=false, @OA\Schema(type="boolean")),
    * @OA\Parameter(name="hasAdminAccount", in="query", required=false, @OA\Schema(type="boolean")),
    * @OA\Response(response=200, description="List of users returned successfully"),
    * @OA\Response(response=400, description="Validation error"),
    * @OA\Response(response=500, description="Server error")
    * )
    */
    public function index(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'domain' => 'required|string',
            'nameFilter' => 'nullable|string',
            'statusFilter' => 'nullable|boolean',
            'hasAdminAccount' => 'nullable|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 400);
        }

        try {
            $this->setLdapConnection($request->domain);
            $searchOus = config('keystone.provisioning.searchBaseOus', []);
            $allUsers = [];

            foreach ($searchOus as $ou) {
                $fullOu = $this->_replaceDomainComponents($ou, $request->domain);
                $query = User::query()->in($fullOu);

                if ($request->filled('nameFilter')) {
                    $query->where('cn', 'contains', $request->nameFilter);
                }

                if ($request->filled('statusFilter')) {
                    // useraccountcontrol flags: 512 = enabled, 514 = disabled
                    $query->where('useraccountcontrol', '=', $request->boolean('statusFilter') ? 512 : 514);
                }

                $users = $query->get();

                foreach ($users as $user) {
                    $adminExists = $this->_checkIfAdminAccountExists($user->samaccountname[0]);
                    if ($request->filled('hasAdminAccount') && $request->boolean('hasAdminAccount') !== $adminExists) {
                        continue;
                    }

                    $allUsers[] = [
                        'samAccountName' => $user->samaccountname[0],
                        'displayName' => $user->displayname[0] ?? null,
                        'isEnabled' => !$user->isDisabled(),
                        'hasAdminAccount' => $adminExists,
                    ];
                }
            }

            return response()->json(collect($allUsers)->sortBy('displayName')->values()->all());

        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to list users: ' . $e->getMessage()], 500);
        }
    }

    /**
    * @OA\Get(
    * path="/api/users/{samAccountName}",
    * summary="Retrieve detailed user information",
    * description="Retrieves detailed information for a specific user based on samAccountName and domain.",
    * tags={"Users"},
    * @OA\Parameter(name="domain", in="query", required=true, @OA\Schema(type="string")),
    * @OA\Parameter(name="samAccountName", in="path", required=true, @OA\Schema(type="string")),
    * @OA\Response(response=200, description="User details retrieved successfully"),
    * @OA\Response(response=400, description="Validation error"),
    * @OA\Response(response=404, description="User not found"),
    * @OA\Response(response=500, description="Server error")
    * )
    */
    public function show(Request $request)
    {
        $validator = Validator::make($request->all(), ['domain' => 'required|string', 'samAccountName' => 'required|string']);
        if ($validator->fails()) return response()->json(['error' => $validator->errors()], 400);

        try {
            $this->setLdapConnection($request->domain);
            $user = User::findBy('samaccountname', $request->samAccountName);

            if (!$user) {
                return response()->json(['error' => 'User not found.'], 404);
            }

            $userDetails = [
                'samAccountName' => $user->samaccountname[0],
                'firstName' => $user->givenname[0] ?? null,
                'lastName' => $user->sn[0] ?? null,
                'displayName' => $user->displayname[0] ?? null,
                'userPrincipalName' => $user->userprincipalname[0] ?? null,
                'emailAddress' => $user->mail[0] ?? null,
                'dateOfBirth' => $user->getFirstAttribute('extensionAttribute1'),
                'mobileNumber' => $user->getFirstAttribute('mobile'),
                'isEnabled' => !$user->isDisabled(),
                'isLockedOut' => $user->isLockedout(),
                'memberOf' => $user->groups()->get()->pluck('cn')->flatten()->toArray(),
                'hasAdminAccount' => $this->_checkIfAdminAccountExists($user->samaccountname[0]),
            ];

            return response()->json($userDetails);

        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to get user details: ' . $e->getMessage()], 500);
        }
    }

    /**
     * Creates a new user in Active Directory with the provided details.
     * Can also create a corresponding admin account if requested.
     *
     * @param Request $request The incoming HTTP request with user data.
     * @return \Illuminate\Http\JsonResponse The new user's account name and initial password.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'domain' => 'required|string',
            'samAccountName' => 'required|string|max:20',
            'firstName' => 'required|string|max:50',
            'lastName' => 'required|string|max:50',
            'dateOfBirth' => 'nullable|string',
            'mobileNumber' => 'nullable|string',
            'optionalGroups' => 'nullable|array',
            'privilegeGroups' => 'nullable|array',
            'createAdminAccount' => 'boolean',
        ]);

        if ($validator->fails()) return response()->json(['error' => $validator->errors()], 400);

        try {
            $this->setLdapConnection($request->domain);

            if (User::findBy('samaccountname', $request->samAccountName)) {
                return response()->json(['error' => 'User already exists.'], 409);
            }

            $user = new User();
            $displayName = $request->firstName . ' ' . $request->lastName;
            $defaultOu = config('keystone.provisioning.ouStandardUser');
            $fullOu = $this->_replaceDomainComponents($defaultOu, $request->domain);

            $user->setDn("cn={$displayName}," . $fullOu);
            $user->samaccountname = $request->samAccountName;
            $user->givenname = $request->firstName;
            $user->sn = $request->lastName;
            $user->displayname = $displayName;
            $user->userprincipalname = $request->samAccountName . '@' . $request->domain;

            if($request->filled('dateOfBirth')) $user->extensionAttribute1 = $request->dateOfBirth;
            if($request->filled('mobileNumber')) $user->mobile = $request->mobileNumber;

            $initialPassword = $this->_generatePassword();
            $user->unicodepwd = Password::encode($initialPassword);
            $user->useraccountcontrol = 512; // Enabled account
            $user->save();
            $user->pwdlastset = 0; // Force password change on next logon
            $user->save();

            // Add to optional groups
            if ($request->filled('optionalGroups')) {
                foreach($request->optionalGroups as $groupDn) {
                    $this->_addUserToGroup($user->samaccountname[0], $this->_replaceDomainComponents($groupDn, $request->domain));
                }
            }

            $response = [
                'samAccountName' => $user->samaccountname[0],
                'initialPassword' => $initialPassword,
            ];

            // Create Admin Account if requested
            if ($request->createAdminAccount) {
                 // TODO: Add privilege check similar to C#'s IsUserHighPrivilege
                $adminResponse = $this->_createAdminAccount($request);
                $response['adminAccountName'] = $adminResponse['samAccountName'];
                $response['adminInitialPassword'] = $adminResponse['initialPassword'];
            }

            return response()->json($response, 201);

        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to create user: ' . $e->getMessage()], 500);
        }
    }

    /**
     * Updates an existing user's attributes, group memberships, and admin account status.
     *
     * @param Request $request The incoming HTTP request with update data.
     * @return \Illuminate\Http\JsonResponse A success message or an error.
     */
    public function update(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'domain' => 'required|string',
            'samAccountName' => 'required|string',
            'dateOfBirth' => 'nullable|string',
            'mobileNumber' => 'nullable|string',
            'optionalGroups' => 'nullable|array',
            'hasAdminAccount' => 'nullable|boolean',
        ]);
        if ($validator->fails()) return response()->json(['error' => $validator->errors()], 400);

        try {
            $this->setLdapConnection($request->domain);
            $user = User::findBy('samaccountname', $request->samAccountName);
            if (!$user) return response()->json(['error' => 'User not found.'], 404);

            // Update attributes
            $user->extensionAttribute1 = $request->dateOfBirth ?? null;
            $user->mobile = $request->mobileNumber ?? null;
            $user->save();

            // Update group membership
            $allOptionalGroups = array_merge(
                config('keystone.provisioning.optionalGroupsForStandardUser', []),
                config('keystone.provisioning.optionalGroupsForHighPrivilegeUsers', [])
            );
            $this->_updateGroupMembership($user, $request->optionalGroups ?? [], $allOptionalGroups);

            // Handle admin account
            if ($request->filled('hasAdminAccount')) {
                // TODO: Add privilege check
                $adminExists = $this->_checkIfAdminAccountExists($user->samaccountname[0]);
                if ($request->hasAdminAccount && !$adminExists) {
                    $createReq = new Request([
                        'samAccountName' => $user->samaccountname[0],
                        'domain' => $request->domain,
                        'firstName' => $user->givenname[0],
                        'lastName' => $user->sn[0],
                        // Pass privilege groups from the original request if available
                        'privilegeGroups' => $request->input('privilegeGroups', [])
                    ]);
                    $this->_createAdminAccount($createReq);
                } else if (!$request->hasAdminAccount && $adminExists) {
                    $this->_disableAdminAccount($user->samaccountname[0] . '-a');
                }
            }

            return response()->json(['success' => 'User updated successfully.']);

        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to update user: ' . $e->getMessage()], 500);
        }
    }

    /**
     * Resets a standard user's password and forces a change on next logon.
     *
     * @param Request $request The incoming HTTP request.
     * @return \Illuminate\Http\JsonResponse The new password or an error message.
     */
    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), ['domain' => 'required|string', 'samAccountName' => 'required|string']);
        if ($validator->fails()) return response()->json(['error' => $validator->errors()], 400);

        try {
            $this->setLdapConnection($request->domain);
            $user = User::findBy('samaccountname', $request->samAccountName);
            if (!$user) return response()->json(['error' => 'User not found.'], 404);

            $newPassword = $this->_generatePassword();
            $user->unicodepwd = Password::encode($newPassword);
            $user->pwdlastset = 0; // Expire password
            $user->save();

            return response()->json(['newPassword' => $newPassword]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to reset password: ' . $e->getMessage()], 500);
        }
    }

    /**
     * Resets an admin account's password. Requires authorization.
     *
     * @param Request $request The incoming HTTP request.
     * @return \Illuminate\Http\JsonResponse The new password or an error message.
     */
    public function resetAdminPassword(Request $request)
    {
        // TODO: Add high privilege check
        $validator = Validator::make($request->all(), ['domain' => 'required|string', 'samAccountName' => 'required|string']);
        if ($validator->fails()) return response()->json(['error' => $validator->errors()], 400);

        try {
            $this->setLdapConnection($request->domain);
            $adminSam = $request->samAccountName . '-a';
            $adminUser = User::findBy('samaccountname', $adminSam);
            if (!$adminUser) return response()->json(['error' => 'Admin account not found.'], 404);

            $newPassword = $this->_generatePassword();
            $adminUser->unicodepwd = Password::encode($newPassword);
            $adminUser->pwdlastset = 0; // Expire password
            $adminUser->save();

            return response()->json(['newPassword' => $newPassword]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to reset admin password: ' . $e->getMessage()], 500);
        }
    }

    /**
     * Unlocks a user's account if it is locked out.
     *
     * @param Request $request The incoming HTTP request.
     * @return \Illuminate\Http\JsonResponse A success message or an error.
     */
    public function unlockAccount(Request $request)
    {
        $validator = Validator::make($request->all(), ['domain' => 'required|string', 'samAccountName' => 'required|string']);
        if ($validator->fails()) return response()->json(['error' => $validator->errors()], 400);

        try {
            $this->setLdapConnection($request->domain);
            $user = User::findBy('samaccountname', $request->samAccountName);
            if (!$user) return response()->json(['error' => 'User not found.'], 404);

            if ($user->isLockedout()) {
                $user->lockouttime = 0;
                $user->save();
            }
            return response()->json(['success' => 'Account unlocked.']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to unlock account: ' . $e->getMessage()], 500);
        }
    }

    /**
     * Disables a user's account in Active Directory.
     *
     * @param Request $request The incoming HTTP request.
     * @return \Illuminate\Http\JsonResponse A success message or an error.
     */
    public function disableAccount(Request $request)
    {
        $validator = Validator::make($request->all(), ['domain' => 'required|string', 'samAccountName' => 'required|string']);
        if ($validator->fails()) return response()->json(['error' => $validator->errors()], 400);

        try {
            $this->setLdapConnection($request->domain);
            $user = User::findBy('samaccountname', $request->samAccountName);
            if (!$user) return response()->json(['error' => 'User not found.'], 404);

            $user->useraccountcontrol = 514; // Set 'disabled' flag
            $user->save();

            return response()->json(['success' => 'Account disabled.']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to disable account: ' . $e->getMessage()], 500);
        }
    }

    /**
    * @OA\Post(
    * path="/api/users/enable",
    * summary="Enable user account",
    * description="Enables a user account in Active Directory (sets userAccountControl flag 512).",
    * tags={"Users"},
    * @OA\RequestBody(
    * required=true,
    * @OA\JsonContent(
    * required={"domain", "samAccountName"},
    * @OA\Property(property="domain", type="string"),
    * @OA\Property(property="samAccountName", type="string")
    * )
    * ),
    * @OA\Response(response=200, description="Account enabled successfully"),
    * @OA\Response(response=404, description="User not found"),
    * @OA\Response(response=500, description="Server error")
    * )
    */
    public function enableAccount(Request $request)
    {
        $validator = Validator::make($request->all(), ['domain' => 'required|string', 'samAccountName' => 'required|string']);
        if ($validator->fails()) return response()->json(['error' => $validator->errors()], 400);

        try {
            $this->setLdapConnection($request->domain);
            $user = User::findBy('samaccountname', $request->samAccountName);
            if (!$user) return response()->json(['error' => 'User not found.'], 404);

            $user->useraccountcontrol = 512; // Unset 'disabled' flag
            $user->save();

            return response()->json(['success' => 'Account enabled.']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to enable account: ' . $e->getMessage()], 500);
        }
    }

    // ------------------ PRIVATE METHODS ------------------

    /**
     * Replaces the {domain-components} placeholder in a string with the LDAP DC format.
     * * @param string $string The string containing the placeholder.
     * @param string $domain The domain to generate components from.
     * @return string The modified string.
     */
    private function _replaceDomainComponents(string $string, string $domain): string
    {
        $domainComponents = 'dc=' . str_replace('.', ',dc=', $domain);
        return str_replace('{domain-components}', $domainComponents, $string);
    }

    /**
     * Dynamically sets the default LDAP connection using service account credentials.
     * It fetches connection details from the .env file and establishes a
     * connection to the specified domain's Active Directory servers.
     *
     * @param string $domain The domain to connect to.
     * @return void
     * @throws \Exception If configuration is missing or connection fails.
     */
    private function setLdapConnection(string $domain): void
    {
        // Get connection details from the .env file
        $hosts = [env('LDAP_HOST')];
        $username = env('LDAP_USERNAME');
        $password = env('LDAP_PASSWORD');
        $baseDn = 'dc=' . str_replace('.', ',dc=', $domain);

        if (empty($hosts[0]) || empty($username) || empty($password)) {
            throw new \Exception("AD connection details (LDAP_HOST, LDAP_USERNAME, LDAP_PASSWORD) are missing in your .env file.");
        }

        $connection = new Connection([
            'hosts' => $hosts,
            'base_dn' => $baseDn,
            'username' => $username,
            'password' => $password,
            'port' => env('LDAP_PORT', 389),
            'use_ssl' => env('LDAP_SSL', false),
            'use_tls' => env('LDAP_TLS', false),
            'version' => 3,
            'timeout' => env('LDAP_TIMEOUT', 5),
            'options' => [
                // Set TLS options based on .env for allowing self-signed certs etc.
                // LDAPTLS_REQCERT=never is equivalent to LDAP_OPT_X_TLS_NEVER
                LDAP_OPT_X_TLS_REQUIRE_CERT => env('LDAP_TLS_INSECURE', false) ? LDAP_OPT_X_TLS_NEVER : LDAP_OPT_X_TLS_DEMAND,
            ]
        ]);

        try {
            $connection->connect();
            Container::addConnection($connection, $domain);
            Container::setDefaultConnection($domain);
            Log::info("Successfully connected to AD for domain {$domain}");
        } catch (LdapRecordException $e) {
            Log::error("Failed to connect to any AD server for domain {$domain}: " . $e->getMessage());
            throw new \Exception("Unable to connect to the configured AD server for domain {$domain}.");
        }
    }

    /**
     * Checks if a corresponding admin account exists for a given base account name.
     *
     * @param string $baseSamAccountName The base user's samAccountName.
     * @return bool True if an admin account (e.g., 'user-a') exists.
     */
    private function _checkIfAdminAccountExists(string $baseSamAccountName): bool
    {
        return User::findBy('samaccountname', $baseSamAccountName . '-a') !== null;
    }

    /**
     * Creates and configures a privileged admin account.
     *
     * @param Request $baseRequest The request data from the original user creation.
     * @return array The new admin account name and its initial password.
     */
    private function _createAdminAccount(Request $baseRequest): array
    {
        $adminSam = $baseRequest->samAccountName . '-a';

        $adminUser = new User();
        $displayName = $baseRequest->firstName . ' ' . $baseRequest->lastName . ' (Admin)';
        $adminOu = config('keystone.provisioning.ouPrivilegeUser');
        $fullAdminOu = $this->_replaceDomainComponents($adminOu, $baseRequest->domain);

        $adminUser->setDn("cn={$displayName}," . $fullAdminOu);
        $adminUser->samaccountname = $adminSam;
        $adminUser->displayname = $displayName;
        $adminUser->userprincipalname = "{$adminSam}@{$baseRequest->domain}";

        $adminPassword = $this->_generatePassword();
        $adminUser->unicodepwd = Password::encode($adminPassword);
        $adminUser->useraccountcontrol = 512;
        $adminUser->save();
        $adminUser->pwdlastset = 0;
        $adminUser->save();

        if ($baseRequest->filled('privilegeGroups')) {
            foreach($baseRequest->privilegeGroups as $groupDn) {
                $this->_addUserToGroup($adminSam, $this->_replaceDomainComponents($groupDn, $baseRequest->domain));
            }
        }

        $domainUsersDn = $this->_replaceDomainComponents('CN=Domain Users,CN=Users,{domain-components}', $baseRequest->domain);
        $this->_removeUserFromGroup($adminSam, $domainUsersDn);

        return ['samAccountName' => $adminSam, 'initialPassword' => $adminPassword];
    }

    /**
     * Disables a specified admin account.
     *
     * @param string $adminSam The samAccountName of the admin to disable.
     * @return void
     */
    private function _disableAdminAccount(string $adminSam): void
    {
        $adminUser = User::findBy('samaccountname', $adminSam);
        if($adminUser) {
            $adminUser->useraccountcontrol = 514;
            $adminUser->save();
        }
    }

    /**
     * Adds a user to a specified Active Directory group by its distinguished name.
     *
     * @param string $userName The user's samAccountName.
     * @param string $groupDn The group's distinguishedName.
     * @return void
     */
    private function _addUserToGroup(string $userName, string $groupDn): void
    {
        try {
            $user = User::findBy('samaccountname', $userName);
            $group = Group::find($groupDn);
            if ($user && $group && !$user->groups()->exists($group)) {
                $user->groups()->attach($group);
            }
        } catch (\Exception $e) {
            Log::error("Failed to add user {$userName} to group {$groupDn}: " . $e->getMessage());
        }
    }

    /**
     * Removes a user from a specified Active Directory group by its distinguished name.
     *
     * @param string $userName The user's samAccountName.
     * @param string $groupDn The group's distinguishedName.
     * @return void
     */
    private function _removeUserFromGroup(string $userName, string $groupDn): void
    {
        try {
            $user = User::findBy('samaccountname', $userName);
            $group = Group::find($groupDn);
            if ($user && $group && $user->groups()->exists($group)) {
                $user->groups()->detach($group);
            }
        } catch (\Exception $e) {
            Log::error("Failed to remove user {$userName} from group {$groupDn}: " . $e->getMessage());
        }
    }

    /**
     * Synchronizes a user's group memberships based on a requested list of groups.
     *
     * @param User $user The user model instance.
     * @param array $requestedGroups The desired list of group distinguished names.
     * @param array $manageableGroups The list of all manageable group distinguished names.
     * @return void
     */
    private function _updateGroupMembership(User $user, array $requestedGroups, array $manageableGroups): void
    {
        $domain = explode('@', $user->userprincipalname[0])[1];

        $manageableGroupsDn = array_map(function($group) use ($domain) {
            return $this->_replaceDomainComponents($group, $domain);
        }, $manageableGroups);

        $currentGroupsDn = $user->groups()
            ->get()
            ->pluck('dn')
            ->flatten()
            ->filter(fn($dn) => in_array($dn, $manageableGroupsDn, true))
            ->toArray();

        $groupsToAdd = array_diff($requestedGroups, $currentGroupsDn);
        $groupsToRemove = array_diff($currentGroupsDn, $requestedGroups);

        foreach($groupsToAdd as $groupDn) $this->_addUserToGroup($user->samaccountname[0], $groupDn);
        foreach($groupsToRemove as $groupDn) $this->_removeUserFromGroup($user->samaccountname[0], $groupDn);
    }

    /**
     * Generates a random, complex password suitable for Active Directory.
     *
     * @return string The generated password.
     */
    private function _generatePassword(): string
    {
        $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lower = 'abcdefghijkmnpqrstuvwxyz';
        $number = '23456789';
        $special = '*$-+?_&=!%{}/';

        $password = Str::random(1) . $upper[random_int(0, strlen($upper) - 1)] .
                    Str::random(1) . $lower[random_int(0, strlen($lower) - 1)] .
                    Str::random(1) . $number[random_int(0, strlen($number) - 1)] .
                    Str::random(1) . $special[random_int(0, strlen($special) - 1)];

        $allChars = $upper . $lower . $number . $special;
        // Ensure password is at least 12 characters long for complexity
        $password .= Str::random(8);

        return str_shuffle($password);
    }
}

