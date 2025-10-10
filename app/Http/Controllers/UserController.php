<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\Container;


class UserController extends Controller
{
    public function index()
    {
        $users = [];
        $connection = Container::getConnection('default');
        // MODIFIED START - 2025-10-10 19:23
        // Fixed bug by changing config key from 'keystone.search_ous' to 'keystone.provisioning.searchBaseOus'.
        $searchOus = config('keystone.provisioning.searchBaseOus');
        // MODIFIED END - 2025-10-10 19:23

        foreach ($searchOus as $ou) {
            $ouUsers = User::in($ou)->get();
            $users = array_merge($users, $ouUsers);
        }

        return view('users.index', ['users' => $users]);
    }

    public function create()
    {
        // Logic to show the create user form
        return view('users.create');
    }

    public function store(Request $request)
    {
        $validatedData = $request->validate([
            'samaccountname' => 'required',
            'cn' => 'required',
            'givenname' => 'required',
            'sn' => 'required',
            'displayname' => 'required',
            'description' => 'nullable',
            'userprincipalname' => 'required|email',
            'password' => 'required|min:8',
        ]);

        try {
            $user = new User();
            $user->samaccountname = $validatedData['samaccountname'];
            $user->cn = $validatedData['cn'];
            $user->givenname = $validatedData['givenname'];
            $user->sn = $validatedData['sn'];
            $user->displayname = $validatedData['displayname'];
            $user->description = $validatedData['description'];
            $user->userprincipalname = $validatedData['userprincipalname'];
            $user->unicodePwd = $validatedData['password'];
            // Set other necessary attributes
            $user->save();

            return redirect()->route('users.index')->with('success', 'User created successfully.');
        } catch (\Exception $e) {
            return redirect()->back()->with('error', 'Failed to create user: ' . $e->getMessage());
        }
    }

    public function enable($guid)
    {
        // MODIFIED START - 2025-10-10 19:23
        // Standardized logic to find user by GUID for consistency.
        $user = User::findByGuid($guid);
        if ($user) {
            $user->userAccountControl = 512; // Normal Account
            $user->save();
            return redirect()->back()->with('success', 'User enabled successfully.');
        }
        return redirect()->back()->with('error', 'User not found.');
        // MODIFIED END - 2025-10-10 19:23
    }
    
    public function disable($guid)
    {
        // MODIFIED START - 2025-10-10 19:23
        // Standardized logic to find user by GUID for consistency.
        $user = User::findByGuid($guid);
        if ($user) {
            $user->userAccountControl = 514; // Account Disabled
            $user->save();
            return redirect()->back()->with('success', 'User disabled successfully.');
        }
        return redirect()->back()->with('error', 'User not found.');
        // MODIFIED END - 2025-10-10 19:23
    }
    

    public function unlock($guid)
    {
        // MODIFIED START - 2025-10-10 19:23
        // Standardized logic to find user by GUID and updated attribute for unlocking.
        $user = User::findByGuid($guid);
        if ($user) {
            $user->lockoutTime = 0;
            $user->save();
            return redirect()->back()->with('success', 'User unlocked successfully.');
        }
        return redirect()->back()->with('error', 'User not found.');
        // MODIFIED END - 2025-10-10 19:23
    }
    
}
