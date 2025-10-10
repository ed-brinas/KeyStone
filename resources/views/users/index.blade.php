<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KeyStone - AD User Management</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
    </style>
</head>
<body class="bg-gray-100">

    <!-- Navigation Bar -->
    <nav class="bg-white shadow-md sticky top-0 z-50">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <!-- Logo / Brand -->
                <div class="flex-shrink-0">
                    <a href="{{ route('users.index') }}" class="text-2xl font-bold text-gray-800">KeyStone</a>
                </div>

                <!-- Navigation Links -->
                <div class="hidden md:block">
                    <div class="ml-10 flex items-baseline space-x-4">
                        <a href="{{ route('users.index') }}" class="bg-blue-600 text-white px-3 py-2 rounded-md text-sm font-medium" aria-current="page">Users</a>
                        <a href="#" class="text-gray-500 hover:bg-gray-200 hover:text-gray-800 px-3 py-2 rounded-md text-sm font-medium">Audit Log</a>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="container mx-auto p-4 sm:p-6 lg:p-8">
        <!-- Page Title -->
        <header class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800">User Search</h1>
            <p class="text-sm text-gray-500">Find and manage Active Directory users.</p>
        </header>

        <!-- Search Card -->
        <div class="bg-white p-6 rounded-lg shadow-md mb-8">
            <form action="{{ route('users.index') }}" method="GET">
                <div class="flex flex-col sm:flex-row gap-4">
                    <!-- Domain Dropdown -->
                    <select name="domain" class="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white">
                        @foreach($domains as $domain)
                            <option value="{{ $domain }}" @if($domain == $selectedDomain) selected @endif>
                                {{ $domain }}
                            </option>
                        @endforeach
                    </select>

                    <input
                        type="text"
                        name="search_query"
                        class="flex-grow w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Enter username, name, or email..."
                        value="{{ $searchQuery ?? '' }}"
                        autofocus
                    >
                    <button
                        type="submit"
                        class="bg-blue-600 text-white font-semibold px-6 py-2 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200"
                    >
                        Search
                    </button>
                </div>
            </form>
        </div>

        <!-- Results Section -->
        @if(isset($searchQuery) && $searchQuery)
            <div class="bg-white rounded-lg shadow-md">
                <div class="p-6 border-b border-gray-200">
                    <h3 class="text-lg font-semibold text-gray-700">Search Results for "{{ $searchQuery }}" in {{ $selectedDomain }}</h3>
                </div>
                <!-- Results Table -->
                <div class="overflow-x-auto">
                    <table class="min-w-full text-sm text-left text-gray-500">
                        <thead class="text-xs text-gray-700 uppercase bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3">Display Name</th>
                                <th scope="col" class="px-6 py-3">Username</th>
                                <th scope="col" class="px-6 py-3">Domain</th>
                                <th scope="col" class="px-6 py-3">Privileged Account</th>
                                <th scope="col" class="px-6 py-3">Expiration Date</th>
                                <th scope="col" class="px-6 py-3">Status</th>
                                <th scope="col" class="px-6 py-3 text-center">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            @if($users->count() > 0)
                                @foreach($users as $user)
                                    <tr class="bg-white border-b hover:bg-gray-50">
                                        <td class="px-6 py-4 font-medium text-gray-900 whitespace-nowrap">
                                            {{ $user->getFirstAttribute('cn') }}
                                        </td>
                                        <td class="px-6 py-4">
                                            {{ $user->getFirstAttribute('samaccountname') }}
                                        </td>
                                        <td class="px-6 py-4">
                                            {{ $selectedDomain }}
                                        </td>
                                        <td class="px-6 py-4">
                                            @if (str_ends_with($user->getFirstAttribute('samaccountname'), '-a'))
                                                <span class="font-semibold text-purple-700">Yes</span>
                                            @else
                                                <span class="text-gray-500">No</span>
                                            @endif
                                        </td>
                                        <td class="px-6 py-4">
                                             {{-- Note: Raw AD dates require formatting in the controller --}}
                                            {{ $user->getAccountExpiry() ? $user->getAccountExpiry()->format('Y-m-d') : 'Never' }}
                                        </td>
                                        <td class="px-6 py-4">
                                            @if ($user->isDisabled())
                                                <span class="px-2 py-1 text-xs font-semibold text-red-800 bg-red-100 rounded-full">Disabled</span>
                                            @else
                                                <span class="px-2 py-1 text-xs font-semibold text-green-800 bg-green-100 rounded-full">Enabled</span>
                                            @endif
                                        </td>
                                        <td class="px-6 py-4">
                                            <div class="flex justify-center items-center space-x-2">
                                                <a href="#" class="text-blue-600 hover:text-blue-900" title="Edit User">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path d="M17.414 2.586a2 2 0 00-2.828 0L7 10.172V13h2.828l7.586-7.586a2 2 0 000-2.828z" /><path fill-rule="evenodd" d="M2 6a2 2 0 012-2h4a1 1 0 010 2H4v10h10v-4a1 1 0 112 0v4a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" clip-rule="evenodd" /></svg>
                                                </a>
                                                 @if ($user->isLocked())
                                                    <a href="#" class="text-yellow-600 hover:text-yellow-900" title="Unlock Account">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" /></svg>
                                                    </a>
                                                @else
                                                    <a href="#" class="text-gray-400 hover:text-gray-600" title="Lock Account">
                                                         <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a5 5 0 00-5 5v2a2 2 0 00-2 2v5a2 2 0 002 2h10a2 2 0 002-2v-5a2 2 0 00-2-2V7a5 5 0 00-5-5zm0 9a1 1 0 100-2 1 1 0 000 2z" /><path d="M9 7a1 1 0 012 0v2a1 1 0 11-2 0V7z" /></svg>
                                                    </a>
                                                @endif
                                                @if ($user->isDisabled())
                                                    <a href="#" class="text-green-600 hover:text-green-900" title="Enable Account">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" /></svg>
                                                    </a>
                                                @else
                                                    <a href="#" class="text-red-600 hover:text-red-900" title="Disable Account">
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>
                                                    </a>
                                                @endif
                                            </div>
                                        </td>
                                    </tr>
                                @endforeach
                            @else
                                <tr>
                                    <td colspan="7" class="px-6 py-12 text-center text-gray-500">
                                        No users found matching your query.
                                    </td>
                                </tr>
                            @endif
                        </tbody>
                    </table>
                </div>
            </div>
        @else
            <div class="text-center text-gray-500 py-16 px-6 bg-white rounded-lg shadow-md">
                <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <h3 class="mt-2 text-sm font-medium text-gray-900">Ready to Search</h3>
                <p class="mt-1 text-sm text-gray-500">Enter a search term above to find an Active Directory user.</p>
            </div>
        @endif
    </main>

</body>
</html>

