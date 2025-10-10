<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use LdapRecord\Models\ActiveDirectory\User;
use Exception;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        // Get the configured LDAP connection names (which should represent your domains)
        $domains = array_keys(config('ldap.connections'));
        $selectedDomain = $request->input('domain', $domains[0] ?? 'default');
        $searchQuery = $request->input('search_query', '');

        $users = [];
        $error = null;

        try {
            // Specify the connection directly on the User model
            $query = User::on($selectedDomain)->query();

            // Apply search query if it exists
            if (!empty($searchQuery)) {
                // Search common user fields
                $query->where(function ($q) use ($searchQuery) {
                    $q->where('cn', 'contains', $searchQuery)
                      ->orWhere('samaccountname', 'contains', $searchQuery)
                      ->orWhere('mail', 'contains', $searchQuery);
                });
            }

            // Limit results for better performance on initial load/broad searches
            $users = $query->limit(100)->get();

        } catch (Exception $e) {
            // Pass the error to the view for user feedback
            $error = 'Could not connect to the LDAP server: ' . $e->getMessage();
        }

        return view('users.index', compact('users', 'domains', 'selectedDomain', 'searchQuery', 'error'));
    }

    /**
     * Show the form for editing the specified user.
     * This is a placeholder for a future module.
     */
    public function edit(Request $request, $guid)
    {
        // Redirect back with an informational message.
        // Full implementation will come in a later module.
        return redirect()->route('users.index')->with('info', 'User editing functionality will be implemented soon.');
    }

    /**
     * Toggles a user's account status (enabled/disabled).
     */
    public function toggleStatus(Request $request, $guid)
    {
        $domain = $request->input('domain');

        try {
            // Find the user on the specified domain connection
            $user = User::on($domain)->findByGuidOrFail($guid);

            if ($user->isDisabled()) {
                $user->enable();
                $message = "User '{$user->getFirstAttribute('cn')}' has been successfully enabled.";
            } else {
                $user->disable();
                $message = "User '{$user->getFirstAttribute('cn')}' has been successfully disabled.";
            }

            $user->save();

            return redirect()->back()->with('success', $message);

        } catch (Exception $e) {
            return redirect()->back()->with('error', 'Failed to update user status: ' . $e->getMessage());
        }
    }

    /**
     * Unlocks a user's account if it is locked.
     */
    public function unlock(Request $request, $guid)
    {
        $domain = $request->input('domain');

        try {
            // Find the user on the specified domain connection
            $user = User::on($domain)->findByGuidOrFail($guid);

            if (!$user->isLocked()) {
                 return redirect()->back()->with('info', "The account for '{$user->getFirstAttribute('cn')}' is not locked.");
            }

            $user->unlock();

            return redirect()->back()->with('success', "The account for '{$user->getFirstAttribute('cn')}' has been unlocked.");

        } catch (Exception $e) {
            return redirect()->back()->with('error', 'Failed to unlock user account: ' . $e->getMessage());
        }
    }
}

