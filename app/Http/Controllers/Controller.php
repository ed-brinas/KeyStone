<?php

namespace App\Http\Controllers;

// MODIFIED START - 2025-10-10 21:23 - Added a helper function to generate random passwords.
abstract class Controller
{
    /**
     * Generate a random, secure password.
     *
     * @param int $length
     * @return string
     */
    protected function generatePassword($length = 16): string
    {
        $sets = [
            'abcdefghijklmnopqrstuvwxyz',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '123456789',
            '!@#$%^&*()_+-=[]{}|'
        ];

        $password = '';
        foreach ($sets as $set) {
            $password .= $set[array_rand(str_split($set))];
        }

        while (strlen($password) < $length) {
            $randomSet = $sets[array_rand($sets)];
            $password .= $randomSet[array_rand(str_split($randomSet))];
        }

        return str_shuffle($password);
    }
}
// MODIFIED END - 2025-10-10 21:23
