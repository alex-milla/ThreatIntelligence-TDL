<?php
/**
 * Create a report (keyword) group from the match-list "Send to report" flow.
 *
 * POST { name, keyword_id? } -> { success, id, name }
 *
 * When keyword_id is given and belongs to the user, the keyword is assigned to
 * the new group (keywords.group_id), so the grouping persists. Creating a group
 * mirrors reports.php's create_group action, just without leaving the page.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
requireAuth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

validateCsrf();

$input = json_decode(file_get_contents('php://input'), true) ?: [];
$name = trim((string)($input['name'] ?? ''));
$keywordId = (int)($input['keyword_id'] ?? 0);
$userId = (int)$_SESSION['user_id'];

if ($name === '') {
    echo json_encode(['success' => false, 'error' => 'Group name cannot be empty.']);
    exit;
}
$nameLen = function_exists('mb_strlen') ? mb_strlen($name) : strlen($name);
if ($nameLen > 60) {
    echo json_encode(['success' => false, 'error' => 'Group name is too long (max 60 characters).']);
    exit;
}

$db = Database::get();
$db->prepare("INSERT INTO keyword_groups (user_id, name) VALUES (?, ?)")->execute([$userId, $name]);
$groupId = (int)$db->lastInsertId();

// Assign the keyword that triggered the group creation (ownership enforced).
if ($keywordId > 0) {
    $db->prepare("UPDATE keywords SET group_id = ? WHERE id = ? AND user_id = ?")
       ->execute([$groupId, $keywordId, $userId]);
}

echo json_encode(['success' => true, 'id' => $groupId, 'name' => $name]);
