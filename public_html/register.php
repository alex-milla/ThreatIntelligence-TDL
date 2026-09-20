<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

if (!empty($_SESSION['user_id'])) {
    header('Location: /');
    exit;
}

$db = Database::get();
$registrationClosed = !isRegistrationOpen($db);

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($registrationClosed) {
        http_response_code(403);
        $error = 'Registration is currently closed.';
    } else {
        validateCsrf();
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        
        if (strlen($username) < 3 || strlen($username) > 30 || !preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $error = 'Username must be 3-30 characters and contain only letters, numbers, and underscores.';
        } elseif (strlen($password) < 8 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Password must be at least 8 characters and email must be valid.';
        } else {
            $db = Database::get();
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, max_keywords) VALUES (?, ?, ?, ?)");
            try {
                $stmt->execute([$username, $email, $hash, DEFAULT_MAX_KEYWORDS]);
                header('Location: /login.php?registered=1');
                exit;
            } catch (PDOException $e) {
                if (strpos($e->getMessage(), 'UNIQUE constraint failed') !== false) {
                    $error = 'Username or email already exists.';
                } else {
                    $error = 'Registration failed. Please try again.';
                }
            }
        }
    }
}

$pageTitle = 'Register';
require __DIR__ . '/templates/header.php';
?>

<div class="card auth-card">
    <div class="auth-logo">
        <i class="material-icons">person_add</i>
        <h2>Create account</h2>
    </div>
    <p class="muted">Register to start monitoring domains</p>
    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <?php if ($registrationClosed): ?>
        <div class="alert alert-error"><i class="material-icons left">lock</i>Registration is currently closed. Contact the administrator.</div>
    <?php else: ?>
    <form method="POST">
        <?php csrfField(); ?>
        <div class="input-field">
            <i class="material-icons prefix">person</i>
            <input id="username" type="text" name="username" class="validate" placeholder=" " required minlength="3">
            <label for="username">Username</label>
        </div>
        <div class="input-field">
            <i class="material-icons prefix">email</i>
            <input id="email" type="email" name="email" class="validate" placeholder=" " required>
            <label for="email">Email</label>
        </div>
        <div class="input-field">
            <i class="material-icons prefix">lock</i>
            <input id="password" type="password" name="password" class="validate" placeholder=" " required minlength="8">
            <label for="password">Password</label>
        </div>
        <button type="submit" class="btn waves-effect" style="width:100%;"><i class="material-icons left">person_add</i>Register</button>
    </form>
    <p style="margin-top: 16px;">Already have an account? <a href="/login.php">Login</a></p>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
