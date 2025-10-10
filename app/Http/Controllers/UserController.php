<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use LdapRecord\Container;
use LdapRecord\Connection;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        // 1. Get domains from the ldap config file.
        // This should be populated from your APPSETTINGS.
        $domains = array_keys(config('ldap.connections'));

        $searchQuery = $request->input('search_query');

        // 2. Get the selected domain from the request, or default to the first one.
        $selectedDomain = $request->input('domain', $domains[0] ?? 'default');

        $users = collect();

        if ($searchQuery) {
            try {
                // 3. Set the default LDAP connection to the one selected in the dropdown.
                Container::setDefault($selectedDomain);
                $connection = Container::getConnection();

                // 4. Perform the search on the selected domain connection.
                $users = $connection->query()
                    ->where(function ($query) use ($searchQuery) {
                        $query->whereContains('samaccountname', $searchQuery)
                              ->orWhereContains('cn', $searchQuery)
                              ->orWhereContains('mail', $searchQuery);
                    })
                    ->limit(100) // Limit results for performance
                    ->get();

            } catch (\Exception $e) {
                // If the connection fails, we can flash an error message.
                // For now, we'll just return an empty result set.
                // In a later module, we will implement proper error handling.
                $users = collect();
            }
        }

        // 5. Pass all necessary data to the view.
        return view('users.index', [
            'users' => $users,
            'searchQuery' => $searchQuery,
            'domains' => $domains,
            'selectedDomain' => $selectedDomain,
        ]);
    }
}

