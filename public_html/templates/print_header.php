<?php
/**
 * Isolated header for the print / PDF document.
 *
 * Loads ONLY /css/print.css (no Materialize, no app.css, no JS bundle), so the
 * browser tab renders exactly like the paper and there is nothing to fight
 * against. The dynamic page margin boxes (report id, TLP, "Page X of Y") are
 * rendered by Paged.js (loaded below); without it they are simply ignored and
 * the browser's own header/footer settings apply.
 *
 * Expected variables (from report_view.php scope): $printTitle, $id, $tlp.
 */
$assetVersion = is_file(__DIR__ . '/../VERSION')
    ? trim((string)file_get_contents(__DIR__ . '/../VERSION'))
    : '0';

$docTitle = (isset($printTitle) && $printTitle !== '') ? $printTitle : 'Domain Threat Report';
$reportId = isset($id) ? (int)$id : 0;
// Strip quotes/backslashes so the value is safe inside a CSS content string.
$tlp = isset($tlp) ? trim((string)$tlp) : '';
$tlpCss = str_replace(['"', '\\'], '', $tlp);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($docTitle) ?></title>
<link rel="stylesheet" href="/css/print.css?v=<?= urlencode($assetVersion) ?>">
<style>
/* Paged.js page margin boxes (dynamic values). Ignored without Paged.js. */
@page {
    @bottom-left {
        content: "ThreatIntelligence-TDL · Report #<?= $reportId ?><?= $tlpCss !== '' ? ' · ' . $tlpCss : '' ?>";
        font-size: 8pt;
        color: #666;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 8pt;
        color: #666;
    }
}
</style>
<script src="https://unpkg.com/pagedjs/dist/paged.polyfill.js"></script>
</head>
<body class="rp-body">
