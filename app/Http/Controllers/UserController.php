<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\Container;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Arr;


class UserController extends Controller
{
    /**
     * Display a list of users based on search criteria and configured OUs.
     */
    public function index(Request $request)
    {
        // Use camelCase keys to access the new config
        $domains = config('keystone.adSettings.domains', array_keys(config('ldap.connections')));
        $selectedDomain = $request->input('domain', Arr::first($domains));
        $searchQuery = $request->input('search_query');

        $users = collect(); // Default to an empty collection

        try {
            // 1. Get the search OU templates from our config file.
            $searchBaseTemplates = config('keystone.provisioning.searchBaseOus');

            if (empty($searchBaseTemplates)) {
                // If the config is missing, return an error to the user.
                return view('users.index', [
                    'users' => $users,
                    'domains' => $domains,
                    'selectedDomain' => $selectedDomain,
                    'searchQuery' => $searchQuery,
                    'error' => 'Configuration Error: "searchBaseOus" is not defined in config/keystone.php.'
                ]);
            }

            // 2. Convert the selected domain (e.g., "ncc.local") into its DC components (e.g., "dc=ncc,dc=local").
            $domainComponents = 'dc=' . str_replace('.', ',dc=', $selectedDomain);

            // 3. Replace the placeholder in each OU template with the actual domain components.
            $searchBases = array_map(function ($template) use ($domainComponents) {
                return str_replace('{domain-components}', $domainComponents, $template);
            }, $searchBaseTemplates);

            // 4. Loop through each search base, perform a query, and merge the results.
            $allFoundUsers = collect();
            foreach ($searchBases as $base) {
                $query = User::on($selectedDomain)->in($base);

                if ($searchQuery) {
                    // Apply search filter if provided
                    $query->where(function ($q) use ($searchQuery) {
                        $q->where('samaccountname', 'contains', $searchQuery)
                          ->orWhere('cn', 'contains', 'like', '%' . $searchQuery . '%');
                    });
                }

                $usersInOu = $query->get();
                $allFoundUsers = $allFoundUsers->merge($usersInOu);
            }

            // 5. Ensure results are unique (in case of overlapping OUs) and sort them by name.
            $users = $allFoundUsers->unique('objectguid')->sortBy('cn');

        } catch (\LdapRecord\LdapRecordException $e) {
            // Enhanced error reporting to help diagnose connection issues.
            $detailedError = $e->getDetailedError();
            $errorMessage = "Could not connect to the LDAP server. Please check the connection details.";

            if ($detailedError && $detailedError->getErrorCode() !== -1) {
                 // Error code -1 is a generic "Can't contact LDAP server"
                $errorMessage = "LDAP Connection Error: {$detailedError->getErrorMessage()} (Code: {$detailedError->getErrorCode()})";
            } else {
                $errorMessage = "Could not connect to the LDAP server. This might be a firewall, DNS, or network issue.";
            }

            Log::error("LDAP Connection Error when searching in '$selectedDomain': " . $e->getMessage());

            return view('users.index', [
                'users' => $users,
                'domains' => $domains,
                'selectedDomain' => $selectedDomain,
                'searchQuery' => $searchQuery,
                'error' => $errorMessage
            ]);

        } catch (\Exception $e) {
             Log::error("An unexpected error occurred in UserController@index: " . $e->getMessage());
             return view('users.index', [
                'users' => $users,
                'domains' => $domains,
                'selectedDomain' => $selectedDomain,
                'searchQuery' => $searchQuery,
                'error' => 'An unexpected error occurred while searching for users.'
            ]);
        }

        return view('users.index', [
            'users' => $users,
            'domains' => $domains,
            'selectedDomain' => $selectedDomain,
            'searchQuery' => $searchQuery,
        ]);
    }

    /**
     * Unlock a user's account.
     */
    public function unlock(Request $request, $guid)
    {
        $domain = $request->input('domain', config('ldap.default'));
        try {
            $user = User::on($domain)->findByGuid($guid);
            if ($user) {
                $user->unlock();
                return back()->with('success', 'User account unlocked successfully.');
            }
            return back()->with('error', 'User not found.');
        } catch (\Exception $e) {
            Log::error("Failed to unlock user with GUID [$guid]: " . $e->getMessage());
            return back()->with('error', 'An error occurred while trying to unlock the user.');
        }
    }

    /**
     * Toggle a user's account status (enabled/disabled).
     */
    public function toggleStatus(Request $request, $guid)
    {
        $domain = $request->input('domain', config('ldap.default'));
        try {
            $user = User::on($domain)->findByGuid($guid);

            if (!$user) {
                return back()->with('error', 'User not found.');
            }

            if ($user->isDisabled()) {
                $user->restore();
                $message = 'User account enabled successfully.';
            } else {
                $user->disable();
                $message = 'User account disabled successfully.';
            }

            return back()->with('success', $message);
        } catch (\Exception $e) {
            Log::error("Failed to toggle status for user with GUID [$guid]: " . $e->getMessage());
            return back()->with('error', 'An error occurred while changing the user account status.');
        }
    }

    /**
     * Show the form for editing a user.
     * (This will be built in the next step)
     */
    public function edit($guid)
    {
        // We will build this functionality next.
        return redirect()->route('users.index')->with('info', 'The "Edit User" page is under construction.');
    }
}

