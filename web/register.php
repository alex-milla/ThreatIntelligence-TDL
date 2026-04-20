<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

if (!empty($_SESSION['user_id'])) {
    header('Location: /');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (strlen($username) < 3 || strlen($password) < 8 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Username must be at least 3 characters, password at least 8, and email must be valid.';
    } else {
        $db = Database::get();
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
        try {
            $stmt->execute([$username, $email, $hash]);
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

$pageTitle = 'Register';
require __DIR__ . '/templates/header.php';
?>

<div class="card" style="max-width: 400px; margin: 60px auto;">
    <h2>Register</h2>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <form method="POST">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" required minlength="3">
        </div>
        <div class="form-group">
            <label>Email</label>
            <input type="email" name="email" required>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" required minlength="8">
        </div>
        <button type="submit" class="btn">Register</button>
    </form>
    <p style="margin-top: 15px;"><a href="/login.php">Already have an account?</a></p>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
