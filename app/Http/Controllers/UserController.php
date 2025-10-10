<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\Container;
use LdapRecord\LdapRecordException;

class UserController extends Controller
{
    // MODIFIED START - 2025-10-10 19:27 - Refactored index method to support multi-domain search and filtering.
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
                          ->orWhere('samaccountname', 'contains', $searchQuery)
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
                       $usersInOus = array_merge($usersInOus, $results);
                    }
                }

                $users = $usersInOus;

            } catch (LdapRecordException $e) {
                $error = "Could not connect or search in LDAP directory for domain '{$selectedDomain}'. Please check the configuration. Error: " . $e->getMessage();
            }
        } else {
            $error = "No domains configured. Please check your keystone.php configuration file.";
        }

        return view('users.index', compact('users', 'domains', 'selectedDomain', 'searchQuery', 'error'));
    }
    // MODIFIED END - 2025-10-10 19:27

    // MODIFIED START - 2025-10-10 19:31 - Fixed "Call to undefined method LdapRecord\ConnectionManager::remove()" error.
    /**
     * Dynamically sets the default LDAP connection.
     *
     * @param string $domain
     * @return void
     */
    private function setLdapConnection(string $domain): void
    {
        // Get the base configuration from config/ldap.php
        $config = config('ldap.connections.default');

        // Dynamically set the base_dn for the selected domain
        $config['base_dn'] = 'dc=' . str_replace('.', ',dc=', $domain);

        // Dynamically set the hosts from the keystone config for the selected domain
        $domainAdServers = config("keystone.adSettings.domain_controllers.{$domain}");
        if (!empty($domainAdServers)) {
            $config['hosts'] = $domainAdServers;
        }

        // Add the dynamically configured connection with the domain name as its unique key.
        Container::addConnection($config, $domain);

        // Set this new connection as the default for all subsequent LDAP operations.
        Container::setDefault($domain);
    }
    // MODIFIED END - 2025-10-10 19:31

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        // MODIFIED START - 2025-10-10 19:27 - Pass domains for modal dropdown.
        $domains = config('keystone.adSettings.domains', []);
        $selectedDomain = $domains[0] ?? null;
        return view('users.index', compact('domains', 'selectedDomain'));
        // MODIFIED END - 2025-10-10 19:27
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        // Placeholder for Phase 3.
        return redirect()->route('users.index')->with('info', 'User creation logic is not yet implemented.');
    }

    // MODIFIED START - 2025-10-10 19:27 - Added placeholder edit method.
    /**
     * Show the form for editing the specified resource.
     */
    public function edit($guid, Request $request)
    {
        // Placeholder for Phase 3.
        return redirect()->route('users.index')->with('info', 'User editing is not yet implemented.');
    }
    // MODIFIED END - 2025-10-10 19:27

    // MODIFIED START - 2025-10-10 19:27 - Implemented toggleStatus method.
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
    // MODIFIED END - 2025-10-10 19:27

    // MODIFIED START - 2025-10-10 19:27 - Updated unlock method to use GUID.
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
    // MODIFIED END - 2025-10-10 19:27
}

