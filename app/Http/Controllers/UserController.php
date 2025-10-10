<canvas>
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\Container;

class UserController extends Controller
{
    public function index()
    {
        // MODIFIED START - 2025-10-10 7:19 PM
        // Initialize LDAP connection
        $connection = Container::getConnection('default');
        // MODIFIED END - 2025-10-10 7:19 PM

        // MODIFIED START - 2025-10-10 7:19 PM
        // Fetch users from all OUs defined in the configuration
        $users = [];
        $ous = config('keystone.search_ous');
        foreach ($ous as $ou) {
            $users = array_merge($users, User::in($ou)->get());
        }
        // MODIFIED END - 2025-10-10 7:19 PM

        return view('users.index', compact('users'));
    }

    public function create()
    {
        return view('users.create');
    }

    public function store(Request $request)
    {
        $request->validate([
            'samaccountname' => 'required|string|max:255',
            'givenname' => 'required|string|max:255',
            'sn' => 'required|string|max:255',
            'mail' => 'required|email|max:255',
        ]);

        // MODIFIED START - 2025-10-10 7:19 PM
        // Create the new user in the default OU
        $user = new User();
        $user->cn = $request->givenname . ' ' . $request->sn;
        $user->samaccountname = $request->samaccountname;
        $user->givenname = $request->givenname;
        $user->sn = $request->sn;
        $user->mail = $request->mail;
        $user->save();
        // MODIFIED END - 2025-10-10 7:19 PM

        return redirect()->route('users.index')->with('success', 'User created successfully.');
    }

    // MODIFIED START - 2025-10-10 7:19 PM
    public function enable(Request $request)
    {
        $user = User::where('samaccountname', '=', $request->samaccountname)->firstOrFail();
        $user->useraccountcontrol = 512; // Enable Account
        $user->save();

        return redirect()->route('users.index')->with('success', 'User enabled successfully.');
    }

    public function disable(Request $request)
    {
        $user = User::where('samaccountname', '=', $request->samaccountname)->firstOrFail();
        $user->useraccountcontrol = 514; // Disable Account
        $user->save();

        return redirect()->route('users.index')->with('success', 'User disabled successfully.');
    }

    public function lock(Request $request)
    {
        $user = User::where('samaccountname', '=', $request->samaccountname)->firstOrFail();
        $user->lockouttime = -1; // Lock Account
        $user->save();

        return redirect()->route('users.index')->with('success', 'User locked successfully.');
    }

    public function unlock(Request $request)
    {
        $user = User::where('samaccountname', '=', $request->samaccountname)->firstOrFail();
        $user->lockouttime = 0; // Unlock Account
        $user->save();

        return redirect()->route('users.index')->with('success', 'User unlocked successfully.');
    }
    // MODIFIED END - 2025-10-10 7:19 PM
}

