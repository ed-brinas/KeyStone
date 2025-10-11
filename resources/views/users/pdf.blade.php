<!DOCTYPE html>
<html>
<head>
    <title>User Details</title>
    <style>
        body {
            font-family: sans-serif;
        }
        .watermark {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-45deg);
            font-size: 100px;
            color: rgba(0, 0, 0, 0.1);
            font-weight: bold;
            z-index: -1;
        }
    </style>
</head>
<body>
    <div class="watermark">Confidential</div>
    <h1>New User Account Details</h1>
    <p><strong>Domain:</strong> {{ $domain }}</p>
    <p><strong>Display Name:</strong> {{ $displayName }}</p>
    <p><strong>Username:</strong> {{ $username }}</p>
    <p><strong>Password:</strong> {{ $password }}</p>
</body>
</html>
