        </div>
    </main>

    <footer class="page-footer grey darken-3">
        <div class="container">
            <div class="row footer-row">
                <div class="col s12 m6">
                    <span class="grey-text text-lighten-3">ThreatIntelligence-TDL &mdash; domain threat monitoring</span>
                </div>
                <div class="col s12 m6 right-align">
                    <span class="grey-text text-lighten-3">v<?= htmlspecialchars(is_file(__DIR__ . '/../VERSION') ? trim(file_get_contents(__DIR__ . '/../VERSION')) : '') ?></span>
                </div>
            </div>
        </div>
    </footer>

    <script src="/js/materialize.min.js"></script>
    <script src="/assets/whois.js"></script>
    <script src="/js/app.js"></script>
</body>
</html>
