        </div>
    </main>

    <?php
    if (!isset($assetVersion)) {
        $assetVersion = is_file(__DIR__ . '/../VERSION') ? trim((string)file_get_contents(__DIR__ . '/../VERSION')) : '0';
    }
    ?>
    <footer class="page-footer">
        <div class="container">
            <div class="row footer-row">
                <div class="col s12 m6">
                    <span class="footer-text">ThreatIntelligence-TDL &mdash; domain threat monitoring</span>
                </div>
                <div class="col s12 m6 right-align">
                    <span class="footer-text">v<?= htmlspecialchars($assetVersion) ?></span>
                </div>
            </div>
        </div>
    </footer>

    <script src="/js/materialize.min.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/assets/whois.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/js/app.js?v=<?= urlencode($assetVersion) ?>"></script>
</body>
</html>
