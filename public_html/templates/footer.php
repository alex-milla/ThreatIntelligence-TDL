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
            <div class="col s12 m8">
                <span class="footer-text">ThreatIntelligence-TDL &mdash; domain threat monitoring</span>
                <span class="footer-text footer-attribution">ccTLD data:
                    <a href="https://www.openintel.nl/" target="_blank" rel="noopener">OpenINTEL</a>
                    (CC BY-NC-SA 4.0) &mdash; a joint project of the University of Twente, SIDN, NLnet Labs and SURF.
                </span>
            </div>
            <div class="col s12 m4 right-align">
                <span class="footer-text">v<?= htmlspecialchars($assetVersion) ?></span>
            </div>
        </div>
        </div>
    </footer>
    </div><!-- .app-body -->
</div><!-- .app-shell -->

    <script src="/js/materialize.min.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/assets/whois.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/assets/vt.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/assets/bulk.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/assets/tracking.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/assets/iocs.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/assets/domain-detail.js?v=<?= urlencode($assetVersion) ?>"></script>
    <script src="/js/app.js?v=<?= urlencode($assetVersion) ?>"></script>
</body>
</html>
