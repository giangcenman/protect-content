// protect-content.js — Bảo vệ website toàn diện (tích hợp devtools-detector)
(function () {
    'use strict';

    // ==================== CẤU HÌNH ====================
    const CONFIG = {
        autoStart: true,
        mode: 'enforce',
        enableDevToolsDetection: true,
        enableScreenshotDetection: true,
        enableMouseProtection: true,
        enableKeyboardProtection: true,
        enableConsoleProtection: true,
        enableNetworkMonitoring: true,
        enableLockdown: false,
        maxViolations: 3,
        lockoutTime: 300000,
        debugMode: false,
        telemetryEndpoint: null,
        telemetryAuthToken: null,
        exposeFingerprintInApi: false
    };

    const LIMITS = {
        devToolsWindowThreshold: 160,
        debuggerDelayThresholdMs: 100,
        keySequenceWindowMs: 2000,
        maxKeySequenceLength: 6,
        rapidClicksPerWindow: 20,
        screenshotHiddenMinMs: 100,
        screenshotHiddenMaxMs: 2000,
        screenshotFocusMinMs: 50,
        screenshotFocusMaxMs: 1000,
        maxMouseMovementSamples: 10,
        maxStoredSecurityEvents: 100,
        maxSuspiciousActivities: 200,
        maxDetailLength: 500,
        maxReasonLength: 200,
        performanceThresholdMultiplier: 10,
        largeObjectKeyCount: 500,
        largeObjectArraySize: 50,
        logThrottleMs: 500,
        mouseAngleThreshold: 5
    };

    const INTERVALS_MS = {
        devToolsSizeCheck: 500,
        devToolsPerformanceCheck: 1000,
        devToolsConsoleCheck: 1000,
        devToolsDebuggerCheck: 3000,
        devToolsFormatterCheck: 2000,
        devToolsErudaCheck: 2000,
        rapidClickWindow: 1000,
        consoleClear: 1000,
        consoleCheck: 500,
        integrityCheck: 5000,
        securityHeartbeat: 30000
    };

    // ==================== LƯU CONSOLE GỐC (trước mọi override) ====================
    const _console = {
        log: console.log.bind(console),
        debug: console.debug.bind(console),
        info: console.info.bind(console),
        warn: console.warn.bind(console),
        error: console.error.bind(console),
        clear: console.clear ? console.clear.bind(console) : function () { },
        table: console.table ? console.table.bind(console) : null
    };

    // ==================== PHÁT HIỆN TRÌNH DUYỆT ====================
    let _browserInfo = null;
    function getBrowserInfo() {
        if (_browserInfo) return _browserInfo;
        const ua = navigator.userAgent;
        _browserInfo = {
            isChrome: /Chrome/.test(ua) && !/Edge|Edg|OPR|Brave/.test(ua),
            isFirefox: /Firefox/.test(ua),
            isSafari: /^((?!chrome|android).)*safari/i.test(ua),
            isEdge: /Edg/.test(ua),
            isOpera: /OPR/.test(ua),
            isBrave: false
        };
        if (navigator.brave && typeof navigator.brave.isBrave === 'function') {
            navigator.brave.isBrave().then(function (r) { _browserInfo.isBrave = r; }).catch(function () { });
        }
        return _browserInfo;
    }
    getBrowserInfo();

    // ==================== LARGE OBJECT (cho Performance Checker) ====================
    let _largeObjectArray = null;
    function getLargeObjectArray() {
        if (_largeObjectArray) return _largeObjectArray;
        const obj = {};
        for (let i = 0; i < LIMITS.largeObjectKeyCount; i++) obj[String(i)] = String(i);
        _largeObjectArray = [];
        for (let i = 0; i < LIMITS.largeObjectArraySize; i++) _largeObjectArray.push(obj);
        return _largeObjectArray;
    }

    // ==================== TRẠNG THÁI ====================
    let securityState = {
        hasInitialized: false,
        sdkActive: false,
        violations: 0,
        isLocked: false,
        lastViolation: 0,
        deviceFingerprint: null,
        sessionStart: Date.now(),
        suspiciousActivity: [],
        lockdownTimer: null,
        isInternalSecurityAction: false,
        lastLogTimestamps: {},
        lastLogCleanup: Date.now(),
        maxPerformanceLogTime: 0,
        performanceWarmupCycles: 0,
        scriptIdentifier: null, // Lưu src của script hiện tại để integrity check
        originalBindings: { fetch: null, xhrOpen: null, webSocket: null, console: null },
        runtimeIntervals: []
    };
    let contentInteractionProtectionInitialized = false;

    // ==================== VĂN BẢN & HẰNG SỐ ====================
    const STORAGE_KEYS = { flaggedDevices: 'flagged_devices', securityEvents: 'security_events' };
    const SECURITY_TEXT = {
        violation: {
            copyAttempt: 'Content copy attempted',
            cutAttempt: 'Content cut attempted',
            pasteAttempt: 'Paste attempted',
            dragBlocked: 'Drag operation blocked',
            devtoolsSize: 'Window size indicates DevTools',
            devtoolsConsole: 'Console access detected',
            devtoolsDebugger: 'Debugger statement delay detected',
            devtoolsPerformance: 'Console performance anomaly detected',
            devtoolsFormatter: 'DevTools custom formatter triggered',
            devtoolsEruda: 'Eruda mobile DevTools detected',
            printScreen: 'Print Screen key detected',
            unnaturalMouse: 'Unnatural mouse movement detected',
            consoleOpened: 'Console panel detected',
            scriptRemoval: 'Security script removed'
        },
        log: {
            securityInitialized: 'Security initialized',
            networkRequestDetected: 'Network request detected',
            xhrRequestDetected: 'XHR request detected',
            websocketDetected: 'WebSocket connection detected',
            violationDetected: (type) => `Violation: ${type}`,
            lockdownTriggered: (reason) => `LOCKDOWN: ${reason}`,
            lockdownReleased: 'Lockdown released',
            javascriptError: 'JavaScript error',
            unhandledRejection: 'Unhandled promise rejection',
            securityHeartbeat: 'Security heartbeat',
            allMeasuresInitialized: 'All security measures initialized',
            initializationFailed: 'Security initialization failed',
            legitimateUseReported: 'Legitimate use reported'
        },
        error: { devtoolsDetected: 'DevTools detected' }
    };
    const VIOLATION_FORMAT = {
        suspiciousPattern: (pattern, timeDiff) => `Pattern: ${pattern.join(',')} | Time: ${timeDiff}ms`,
        rapidClicking: (clickCount) => `${clickCount} clicks in 1 second`,
        potentialScreenshotHidden: (hiddenTime) => `Hidden for ${hiddenTime}ms`,
        potentialScreenshotFocus: (blurTime) => `Focus lost for ${blurTime}ms`,
        automationDetected: (count) => `${count} indicators found`,
        consoleUsage: (method) => `Console.${method} called`,
        functionTampering: (funcName) => `${funcName} has been modified`,
        performanceTiming: (tTime, lTime) => `Table: ${tTime.toFixed(1)}ms vs Log: ${lTime.toFixed(1)}ms`
    };
    const VIOLATION_TEXT = SECURITY_TEXT.violation;
    const LOG_TEXT = SECURITY_TEXT.log;
    const ERROR_TEXT = SECURITY_TEXT.error;
    const INTEGRITY_MARKER = '__PROTECT_CONTENT_ACTIVE__';

    // ==================== HELPER FUNCTIONS ====================
    function isEditableTarget(t) {
        return t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.contentEditable === 'true';
    }
    function isEnforceMode() { return CONFIG.mode !== 'monitor'; }
    function isSdkActive() { return securityState.sdkActive; }

    function managedSetInterval(cb, ms) {
        const id = setInterval(cb, ms);
        securityState.runtimeIntervals.push(id);
        return id;
    }
    function clearManagedIntervals() {
        securityState.runtimeIntervals.forEach(id => clearInterval(id));
        securityState.runtimeIntervals = [];
    }

    function applyRuntimeConfig(overrides = {}) {
        if (!overrides || typeof overrides !== 'object') return;
        Object.keys(CONFIG).forEach(key => {
            if (Object.prototype.hasOwnProperty.call(overrides, key)) CONFIG[key] = overrides[key];
        });
        if (CONFIG.mode !== 'enforce' && CONFIG.mode !== 'monitor') CONFIG.mode = 'enforce';
    }

    function restoreOriginalBindings() {
        if (securityState.originalBindings.fetch) window.fetch = securityState.originalBindings.fetch;
        if (securityState.originalBindings.xhrOpen) window.XMLHttpRequest.prototype.open = securityState.originalBindings.xhrOpen;
        if (securityState.originalBindings.webSocket) window.WebSocket = securityState.originalBindings.webSocket;
        if (securityState.originalBindings.console) {
            ['log', 'debug', 'info', 'warn', 'error'].forEach(m => {
                if (securityState.originalBindings.console[m]) console[m] = securityState.originalBindings.console[m];
            });
        }
    }

    function getPublicSecurityState() {
        return {
            initialized: securityState.hasInitialized,
            active: securityState.sdkActive,
            mode: CONFIG.mode,
            violations: securityState.violations,
            isLocked: securityState.isLocked,
            sessionStart: securityState.sessionStart
        };
    }

    function stopSecurity() {
        securityState.sdkActive = false;
        securityState.isLocked = false;
        securityState.violations = 0;
        if (securityState.lockdownTimer) {
            clearTimeout(securityState.lockdownTimer);
            securityState.lockdownTimer = null;
        }
        clearLockdownOverlay();
        clearManagedIntervals();
        restoreOriginalBindings();
        securityState.originalBindings = { fetch: null, xhrOpen: null, webSocket: null, console: null };
        securityState.hasInitialized = false;
    }

    function startSecurity() {
        if (securityState.hasInitialized) {
            securityState.sdkActive = true;
            return getPublicSecurityState();
        }
        securityState.sessionStart = Date.now();
        securityState.sdkActive = true;
        initializeAllSecurity();
        securityState.hasInitialized = true;
        return getPublicSecurityState();
    }

    function toSafeString(value, maxLength = LIMITS.maxDetailLength) {
        try {
            const text = typeof value === 'string' ? value : JSON.stringify(value);
            return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
        } catch (e) {
            const fallback = String(value);
            return fallback.length > maxLength ? `${fallback.slice(0, maxLength)}...` : fallback;
        }
    }

    function isTelemetryRequest(input) {
        if (!CONFIG.telemetryEndpoint) return false;
        try {
            const url = typeof input === 'string' ? input : input?.url;
            if (!url) return false;
            return new URL(url, location.href).href === new URL(CONFIG.telemetryEndpoint, location.href).href;
        } catch (e) { return false; }
    }

    function getPersistentStorageKey(key) { return `security:${key}`; }

    // ==================== LOCKDOWN OVERLAY (Fixed XSS — dùng textContent) ====================
    function renderLockdownOverlay(reason) {
        const existing = document.getElementById('security-lockdown-overlay');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'security-lockdown-overlay';
        overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,0.92);color:#fff;display:flex;align-items:center;justify-content:center;font-family:Arial,sans-serif;text-align:center;padding:24px;';

        const container = document.createElement('div');
        const h1 = document.createElement('h1');
        h1.style.cssText = 'font-size:28px;margin-bottom:12px;';
        h1.textContent = 'Access temporarily restricted';
        const p1 = document.createElement('p');
        p1.style.cssText = 'font-size:16px;margin-bottom:8px;';
        p1.textContent = 'Website is protected';
        const p2 = document.createElement('p');
        p2.style.cssText = 'font-size:14px;opacity:0.8;';
        p2.textContent = 'Reason: ' + toSafeString(reason, LIMITS.maxReasonLength);
        container.append(h1, p1, p2);
        overlay.appendChild(container);
        document.body.appendChild(overlay);
    }

    function clearLockdownOverlay() {
        const o = document.getElementById('security-lockdown-overlay');
        if (o) o.remove();
    }

    // ==================== TELEMETRY ====================
    function reportSecurityEventToServer(event) {
        if (!CONFIG.telemetryEndpoint || securityState.isInternalSecurityAction) return;
        try {
            securityState.isInternalSecurityAction = true;
            const payload = JSON.stringify({ ...event, page: location.href });
            if (navigator.sendBeacon) {
                navigator.sendBeacon(CONFIG.telemetryEndpoint, new Blob([payload], { type: 'application/json' }));
            } else {
                const headers = { 'Content-Type': 'application/json' };
                if (CONFIG.telemetryAuthToken) headers['Authorization'] = `Bearer ${CONFIG.telemetryAuthToken}`;
                fetch(CONFIG.telemetryEndpoint, { method: 'POST', headers, body: payload, keepalive: true, credentials: 'omit' }).catch(() => { });
            }
        } catch (e) { } finally { securityState.isInternalSecurityAction = false; }
    }

    // ==================== FINGERPRINT ====================
    function generateFingerprint() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Device fingerprint', 2, 2);
        let pluginNames = '';
        try { pluginNames = Array.from(navigator.plugins || []).map(p => p.name).join(','); } catch (e) { }
        return btoa(JSON.stringify({
            screen: `${screen.width}x${screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            platform: navigator.platform,
            canvas: canvas.toDataURL(),
            webgl: getWebGLFingerprint(),
            plugins: pluginNames,
            userAgent: navigator.userAgent.slice(0, 100)
        }));
    }

    function getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return 'no-webgl';
            const dbg = gl.getExtension('WEBGL_debug_renderer_info');
            return dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : 'webgl-available';
        } catch (e) { return 'webgl-error'; }
    }

    // ==================== STORAGE ====================
    function storeData(key, data) {
        try {
            localStorage.setItem(getPersistentStorageKey(key), btoa(JSON.stringify({ version: 1, timestamp: Date.now(), data })));
        } catch (e) { }
    }

    function getLegacyStoredData(key) {
        try {
            const matchingKey = Object.keys(localStorage).find(k => {
                try { return atob(k).startsWith(key + '_security_'); } catch (e) { return false; }
            });
            if (!matchingKey) return null;
            const raw = localStorage.getItem(matchingKey);
            return raw ? JSON.parse(atob(raw)) : null;
        } catch (e) { return null; }
    }

    function getStoredData(key) {
        try {
            const encoded = localStorage.getItem(getPersistentStorageKey(key));
            if (encoded) {
                const decoded = JSON.parse(atob(encoded));
                return decoded && typeof decoded === 'object' && 'data' in decoded ? decoded.data : decoded;
            }
            const legacy = getLegacyStoredData(key);
            if (legacy !== null) { storeData(key, legacy); return legacy; }
        } catch (e) { }
        return null;
    }

    // ==================== LOG BẢO MẬT (có throttle) ====================
    function logSecurityEvent(message, level = 'info', details = null) {
        const now = Date.now();
        const throttleKey = message + '|' + level;

        // Throttle: không ghi cùng một message quá nhanh
        if (securityState.lastLogTimestamps[throttleKey] && now - securityState.lastLogTimestamps[throttleKey] < LIMITS.logThrottleMs) {
            return;
        }
        securityState.lastLogTimestamps[throttleKey] = now;

        // Cleanup throttle map mỗi 60 giây để tránh memory leak
        if (now - securityState.lastLogCleanup > 60000) {
            const keys = Object.keys(securityState.lastLogTimestamps);
            keys.forEach(k => {
                if (now - securityState.lastLogTimestamps[k] > 60000) delete securityState.lastLogTimestamps[k];
            });
            securityState.lastLogCleanup = now;
        }

        const event = {
            timestamp: new Date().toISOString(),
            level,
            message,
            details: details ? toSafeString(details) : null,
            fingerprint: securityState.deviceFingerprint,
            violations: securityState.violations,
            sessionTime: now - securityState.sessionStart
        };

        if (CONFIG.debugMode && _console.log) _console.log('Security Event:', event);
        reportSecurityEventToServer(event);

        const events = getStoredData(STORAGE_KEYS.securityEvents) || [];
        events.push(event);
        if (events.length > LIMITS.maxStoredSecurityEvents) events.shift();
        storeData(STORAGE_KEYS.securityEvents, events);
    }

    // ==================== INIT SECURITY ====================
    function initSecurity() {
        securityState.deviceFingerprint = generateFingerprint();
        securityState.scriptIdentifier = detectScriptIdentifier();
        if (!CONFIG.enableLockdown) {
            logSecurityEvent(LOG_TEXT.securityInitialized, 'info');
            return;
        }
        const flaggedDevices = getStoredData(STORAGE_KEYS.flaggedDevices) || [];
        if (flaggedDevices.includes(securityState.deviceFingerprint)) {
            triggerLockdown('Device flagged');
            return;
        }
        logSecurityEvent(LOG_TEXT.securityInitialized, 'info');
    }

    // ==================== VIOLATION HANDLING ====================
    function handleViolation(type, details = null) {
        if (!isSdkActive() || securityState.isLocked) return;
        securityState.violations += 1;
        securityState.lastViolation = Date.now();
        const record = { type, details: toSafeString(details), timestamp: Date.now(), fingerprint: securityState.deviceFingerprint };
        securityState.suspiciousActivity.push(record);
        if (securityState.suspiciousActivity.length > LIMITS.maxSuspiciousActivities) securityState.suspiciousActivity.shift();
        logSecurityEvent(LOG_TEXT.violationDetected(type), 'warning', record.details);
        if (CONFIG.enableLockdown && securityState.violations >= CONFIG.maxViolations) {
            triggerLockdown(`Multiple violations (${securityState.violations})`);
        }
    }

    function triggerLockdown(reason) {
        if (!CONFIG.enableLockdown || securityState.isLocked) return;
        securityState.isLocked = true;
        const safeReason = toSafeString(reason, LIMITS.maxReasonLength);
        const flagged = getStoredData(STORAGE_KEYS.flaggedDevices) || [];
        if (!flagged.includes(securityState.deviceFingerprint)) {
            flagged.push(securityState.deviceFingerprint);
            storeData(STORAGE_KEYS.flaggedDevices, flagged);
        }
        logSecurityEvent(LOG_TEXT.lockdownTriggered(safeReason), 'critical');
        renderLockdownOverlay(safeReason);
        if (securityState.lockdownTimer) clearTimeout(securityState.lockdownTimer);
        securityState.lockdownTimer = setTimeout(() => {
            securityState.isLocked = false;
            securityState.violations = 0;
            clearLockdownOverlay();
            logSecurityEvent(LOG_TEXT.lockdownReleased, 'info');
        }, CONFIG.lockoutTime);
    }

    function isDevToolsWindowOpen(threshold = LIMITS.devToolsWindowThreshold) {
        return window.outerHeight - window.innerHeight > threshold || window.outerWidth - window.innerWidth > threshold;
    }

    // ==================== CONTENT INTERACTION PROTECTION ====================
    function initContentInteractionProtection() {
        if (contentInteractionProtectionInitialized) return;
        contentInteractionProtectionInitialized = true;

        ['copy', 'paste', 'cut'].forEach(evt => {
            document.addEventListener(evt, function (e) {
                if (!isSdkActive()) return true;
                if (!isEnforceMode()) {
                    if (evt === 'copy') handleViolation('copy_attempt', VIOLATION_TEXT.copyAttempt);
                    else if (evt === 'cut') handleViolation('cut_attempt', VIOLATION_TEXT.cutAttempt);
                    else if (evt === 'paste') handleViolation('paste_attempt', VIOLATION_TEXT.pasteAttempt);
                    return true;
                }
                e.preventDefault(); e.stopPropagation();
                if (evt === 'copy') { e.clipboardData?.setData('text/plain', ''); handleViolation('copy_attempt', VIOLATION_TEXT.copyAttempt); }
                else if (evt === 'cut') handleViolation('cut_attempt', VIOLATION_TEXT.cutAttempt);
                else if (evt === 'paste') handleViolation('paste_attempt', VIOLATION_TEXT.pasteAttempt);
                return false;
            });
        });

        document.addEventListener('selectstart', function (e) {
            if (!isSdkActive() || !isEnforceMode()) return true;
            if (isEditableTarget(e.target)) return true;
            e.preventDefault(); return false;
        });

        ['dragstart', 'drag', 'dragend', 'dragover', 'dragenter', 'dragleave', 'drop'].forEach(evt => {
            document.addEventListener(evt, function (e) {
                if (!isSdkActive()) return true;
                if (!isEnforceMode()) {
                    if (evt === 'dragstart') handleViolation('drag_attempt', VIOLATION_TEXT.dragBlocked);
                    return true;
                }
                e.preventDefault(); e.stopPropagation();
                if (evt === 'dragstart') handleViolation('drag_attempt', VIOLATION_TEXT.dragBlocked);
                return false;
            });
        });
    }

    // ==================== DEVTOOLS DETECTION (6 phương pháp từ devtools-detector) ====================
    function initDevToolsDetection() {
        if (!CONFIG.enableDevToolsDetection) return;
        let devToolsOpen = false;

        // 1. Window Size Check (500ms interval)
        managedSetInterval(() => {
            if (!isSdkActive()) return;
            const isOpen = isDevToolsWindowOpen();
            if (isOpen && !devToolsOpen) { devToolsOpen = true; handleViolation('devtools_size', VIOLATION_TEXT.devtoolsSize); }
            else if (!isOpen && devToolsOpen) { devToolsOpen = false; }
        }, INTERVALS_MS.devToolsSizeCheck);

        // 2. Performance Checker — phương pháp mạnh nhất (từ devtools-detector)
        // Nguyên lý: console.table tạo DOM nodes khi DevTools mở → chậm gấp 10x+
        // Cần warm-up 3 cycles đầu để thu thập baseline ổn định trước khi so sánh
        if (_console.table) {
            const WARMUP_CYCLES = 3;
            managedSetInterval(() => {
                if (!isSdkActive()) return;
                try {
                    const arr = getLargeObjectArray();
                    // Baseline: console.log time
                    let s = performance.now(); _console.log(arr); const lt1 = performance.now() - s;
                    s = performance.now(); _console.log(arr); const lt2 = performance.now() - s;
                    const logTime = Math.max(lt1, lt2);
                    securityState.maxPerformanceLogTime = Math.max(securityState.maxPerformanceLogTime, logTime);
                    // Test: console.table time
                    s = performance.now(); _console.table(arr); const tableTime = performance.now() - s;
                    _console.clear();

                    // Warm-up: thu thập baseline trước khi so sánh
                    securityState.performanceWarmupCycles++;
                    if (securityState.performanceWarmupCycles <= WARMUP_CYCLES) return;

                    if (tableTime === 0) return;
                    if (securityState.maxPerformanceLogTime === 0) {
                        if (getBrowserInfo().isBrave) handleViolation('devtools_performance', VIOLATION_TEXT.devtoolsPerformance);
                        return;
                    }
                    if (tableTime > securityState.maxPerformanceLogTime * LIMITS.performanceThresholdMultiplier) {
                        handleViolation('devtools_performance', VIOLATION_FORMAT.performanceTiming(tableTime, securityState.maxPerformanceLogTime));
                    }
                } catch (e) { }
            }, INTERVALS_MS.devToolsPerformanceCheck);
        }

        // 3. Element ID Getter (chỉ hiệu quả trên Safari — Chrome đã vô hiệu hóa)
        const browser = getBrowserInfo();
        if (browser.isSafari) {
            const el = document.createElement('div');
            Object.defineProperty(el, 'id', {
                get() { handleViolation('devtools_console', VIOLATION_TEXT.devtoolsConsole); return 'sc'; },
                configurable: true
            });
            managedSetInterval(() => {
                if (!isSdkActive()) return;
                try { _console.log(el); _console.clear(); } catch (e) { }
            }, INTERVALS_MS.devToolsConsoleCheck);
        }

        // 4. Debugger Timing (constructor trick — khó bypass hơn debugger trực tiếp)
        managedSetInterval(() => {
            if (!isSdkActive()) return;
            const start = performance.now();
            try { (function () { }).constructor('debugger')(); } catch (e) {
                // CSP chặn constructor → bỏ qua, không fallback debugger trực tiếp để tránh ảnh hưởng UX
            }
            if (performance.now() - start > LIMITS.debuggerDelayThresholdMs) {
                handleViolation('devtools_debugger', VIOLATION_TEXT.devtoolsDebugger);
            }
        }, INTERVALS_MS.devToolsDebuggerCheck);

        // 5. DevTools Custom Formatters (từ devtools-detector)
        // Khi user bật "Custom formatters" trong DevTools settings → header() được gọi
        let fmtOpen = false;
        const devtoolsFormatter = { header() { fmtOpen = true; return null; }, hasBody() { return false; } };
        managedSetInterval(() => {
            if (!isSdkActive()) return;
            try {
                if (window.devtoolsFormatters) {
                    if (window.devtoolsFormatters.indexOf(devtoolsFormatter) === -1) window.devtoolsFormatters.push(devtoolsFormatter);
                } else { window.devtoolsFormatters = [devtoolsFormatter]; }
                fmtOpen = false;
                _console.log({}); _console.clear();
                if (fmtOpen) handleViolation('devtools_formatter', VIOLATION_TEXT.devtoolsFormatter);
            } catch (e) { }
        }, INTERVALS_MS.devToolsFormatterCheck);

        // 6. Eruda Mobile DevTools (từ devtools-detector)
        managedSetInterval(() => {
            if (!isSdkActive()) return;
            try {
                if (typeof window.eruda !== 'undefined' && window.eruda && window.eruda._devTools && window.eruda._devTools._isShow === true) {
                    handleViolation('devtools_eruda', VIOLATION_TEXT.devtoolsEruda);
                }
            } catch (e) { }
        }, INTERVALS_MS.devToolsErudaCheck);
    }

    // ==================== KEYBOARD PROTECTION (chỉ chặn phím liên quan DevTools/source) ====================
    function initKeyboardProtection() {
        if (!CONFIG.enableKeyboardProtection) return;

        const blockedKeys = [
            { key: 123 },                          // F12
            { ctrl: true, shift: true, key: 73 },  // Ctrl+Shift+I
            { ctrl: true, shift: true, key: 74 },  // Ctrl+Shift+J
            { ctrl: true, shift: true, key: 67 },  // Ctrl+Shift+C
            { ctrl: true, shift: true, key: 75 },  // Ctrl+Shift+K (Firefox)
            { ctrl: true, shift: true, key: 69 },  // Ctrl+Shift+E (Firefox)
            { ctrl: true, key: 85 },                // Ctrl+U (View Source)
            { ctrl: true, key: 83 },                // Ctrl+S (Save Page)
            { ctrl: true, key: 65 },                // Ctrl+A (Select All)
            { ctrl: true, key: 80 },                // Ctrl+P (Print)
            { key: 44 },                            // Print Screen
            { key: 44, alt: true },                 // Alt+PrtSc
            { key: 44, win: true },                 // Win+PrtSc
            { key: 71, win: true },                 // Win+G (Game Bar)
            { key: 73, cmd: true, alt: true },      // Cmd+Alt+I
            { key: 67, cmd: true, alt: true },      // Cmd+Alt+C
            { key: 74, cmd: true, alt: true },      // Cmd+Alt+J
            { key: 51, cmd: true, shift: true },    // Cmd+Shift+3
            { key: 52, cmd: true, shift: true },    // Cmd+Shift+4
            { key: 53, cmd: true, shift: true },    // Cmd+Shift+5
        ];

        document.addEventListener('keydown', function (e) {
            if (!isSdkActive()) return true;
            const isWinKey = e.key === 'Meta' || e.metaKey || e.key === 'OS' || e.keyCode === 91 || e.keyCode === 92;
            const isCmdKey = e.metaKey || e.key === 'Meta' || e.keyCode === 91 || e.keyCode === 93;

            const blocked = blockedKeys.some(c => {
                const keyM = c.key === e.keyCode || c.key === e.which;
                return keyM && (!c.ctrl || e.ctrlKey) && (!c.shift || e.shiftKey) && (!c.alt || e.altKey) && (!c.win || isWinKey) && (!c.cmd || isCmdKey);
            });

            const isPrintScreen = e.key === 'PrintScreen' || e.code === 'PrintScreen' || e.keyCode === 44;
            const isGameBar = isWinKey && (e.keyCode === 71 || e.key === 'g' || e.key === 'G');
            const isMacSS = isCmdKey && e.shiftKey && [51, 52, 53].includes(e.keyCode);
            const isCtxMenu = e.keyCode === 93 || e.key === 'ContextMenu';

            if (blocked || isPrintScreen || isGameBar || isMacSS || isCtxMenu) {
                let vType = 'blocked_shortcut';
                if (isPrintScreen || isGameBar || isMacSS) vType = 'screenshot_attempt';
                else if (isCtxMenu) vType = 'context_menu_blocked';

                if (!isEnforceMode()) { handleViolation(vType, `Key: ${e.keyCode}`); return true; }
                e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
                handleViolation(vType, `Key: ${e.keyCode}`);
                if (typeof e.returnValue !== 'undefined') e.returnValue = false;
                return false;
            }
        }, true);

        // Phát hiện chuỗi phím đáng ngờ
        let keySeq = [], keyTimes = [];
        document.addEventListener('keydown', function (e) {
            if (!isSdkActive()) return;
            const now = Date.now();
            while (keyTimes.length > 0 && keyTimes[0] < now - LIMITS.keySequenceWindowMs) { keySeq.shift(); keyTimes.shift(); }
            keySeq.push(e.keyCode); keyTimes.push(now);
            if (keySeq.length > LIMITS.maxKeySequenceLength) { keySeq.shift(); keyTimes.shift(); }

            const patterns = [[17, 85], [17, 16, 73], [17, 16, 74], [17, 16, 67], [17, 16, 75], [123], [44], [91, 71], [92, 71]];
            patterns.forEach(p => {
                if (keySeq.length >= p.length) {
                    const recent = keySeq.slice(-p.length);
                    if (recent.every((k, i) => k === p[i])) {
                        const times = keyTimes.slice(-p.length);
                        handleViolation('suspicious_key_pattern', VIOLATION_FORMAT.suspiciousPattern(p, times[times.length - 1] - times[0]));
                    }
                }
            });
        });

        initContentInteractionProtection();
    }

    // ==================== MOUSE PROTECTION ====================
    function initMouseProtection() {
        if (!CONFIG.enableMouseProtection) return;

        document.addEventListener('contextmenu', function (e) {
            if (!isSdkActive()) return true;
            if (!isEnforceMode()) { handleViolation('context_menu_blocked', 'Context menu'); return true; }
            e.preventDefault();
            e.target.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, clientX: e.clientX, clientY: e.clientY, button: 0, buttons: 1 }));
            return false;
        });

        let clickCount = 0, clickTimer = null;
        document.addEventListener('click', function () {
            if (!isSdkActive()) return;
            clickCount++;
            if (clickTimer) clearTimeout(clickTimer);
            clickTimer = setTimeout(() => {
                if (clickCount > LIMITS.rapidClicksPerWindow) handleViolation('rapid_clicking', VIOLATION_FORMAT.rapidClicking(clickCount));
                clickCount = 0;
            }, INTERVALS_MS.rapidClickWindow);
        });

        initContentInteractionProtection();
    }

    // ==================== NETWORK MONITORING ====================
    function initNetworkMonitoring() {
        if (!CONFIG.enableNetworkMonitoring || securityState.originalBindings.fetch) return;

        const origFetch = window.fetch;
        securityState.originalBindings.fetch = origFetch;
        window.fetch = function (...args) {
            if (!securityState.isInternalSecurityAction && !isTelemetryRequest(args[0]))
                logSecurityEvent(LOG_TEXT.networkRequestDetected, 'info', toSafeString(args[0]));
            return origFetch.apply(this, args);
        };

        const origXHR = XMLHttpRequest.prototype.open;
        securityState.originalBindings.xhrOpen = origXHR;
        XMLHttpRequest.prototype.open = function (method, url) {
            if (!securityState.isInternalSecurityAction && !isTelemetryRequest(url))
                logSecurityEvent(LOG_TEXT.xhrRequestDetected, 'info', `${method} ${url}`);
            return origXHR.apply(this, arguments);
        };

        const origWS = window.WebSocket;
        securityState.originalBindings.webSocket = origWS;
        const WS = function (url, protocols) {
            if (!securityState.isInternalSecurityAction) logSecurityEvent(LOG_TEXT.websocketDetected, 'warning', toSafeString(url));
            return protocols !== undefined ? new origWS(url, protocols) : new origWS(url);
        };
        WS.prototype = origWS.prototype;
        Object.setPrototypeOf(WS, origWS);
        window.WebSocket = WS;
    }

    // ==================== SCREENSHOT DETECTION ====================
    function initScreenshotDetection() {
        if (!CONFIG.enableScreenshotDetection) return;

        let visTimer = null;
        document.addEventListener('visibilitychange', function () {
            if (!isSdkActive()) return;
            if (document.hidden) { visTimer = Date.now(); }
            else if (visTimer) {
                const t = Date.now() - visTimer;
                if (t > LIMITS.screenshotHiddenMinMs && t < LIMITS.screenshotHiddenMaxMs)
                    handleViolation('potential_screenshot', VIOLATION_FORMAT.potentialScreenshotHidden(t));
                visTimer = null;
            }
        });

        let focusLoss = null;
        window.addEventListener('blur', function () {
            if (!isSdkActive()) return;
            focusLoss = Date.now();
            document.body.style.filter = 'blur(10px)';
        });
        window.addEventListener('focus', function () {
            if (!isSdkActive()) return;
            document.body.style.filter = 'none';
            if (focusLoss) {
                const t = Date.now() - focusLoss;
                if (t > LIMITS.screenshotFocusMinMs && t < LIMITS.screenshotFocusMaxMs)
                    handleViolation('potential_screenshot', VIOLATION_FORMAT.potentialScreenshotFocus(t));
                focusLoss = null;
            }
        });

        document.addEventListener('keyup', function (e) {
            if (!isSdkActive()) return;
            if (e.keyCode === 44 || e.key === 'PrintScreen') handleViolation('print_screen', VIOLATION_TEXT.printScreen);
        });
    }

    // ==================== AUTOMATION DETECTION (cải thiện mouse — tính góc) ====================
    function initAutomationDetection() {
        const checks = [
            () => navigator.webdriver,
            () => window.phantom || window.callPhantom,
            () => window.Buffer,
            () => window.emit,
            () => window.spawn,
            () => navigator.userAgent.includes('HeadlessChrome'),
            () => navigator.userAgent.includes('PhantomJS'),
            () => !window.chrome && /Chrome/.test(navigator.userAgent) && !getBrowserInfo().isFirefox
        ];
        const detected = checks.filter(c => { try { return c(); } catch (e) { return false; } });
        if (detected.length > 0) handleViolation('automation_detected', VIOLATION_FORMAT.automationDetected(detected.length));

        // Mouse movement — tính góc và variance tốc độ thay vì chỉ delta < 2
        let moves = [];
        document.addEventListener('mousemove', function (e) {
            if (!isSdkActive()) return;
            moves.push({ x: e.clientX, y: e.clientY, t: Date.now() });
            if (moves.length > LIMITS.maxMouseMovementSamples) moves.shift();
            if (moves.length >= 5) {
                const angles = [];
                for (let i = 2; i < moves.length; i++) {
                    const dx1 = moves[i - 1].x - moves[i - 2].x, dy1 = moves[i - 1].y - moves[i - 2].y;
                    const dx2 = moves[i].x - moves[i - 1].x, dy2 = moves[i].y - moves[i - 1].y;
                    const l1 = Math.sqrt(dx1 * dx1 + dy1 * dy1), l2 = Math.sqrt(dx2 * dx2 + dy2 * dy2);
                    if (l1 > 0 && l2 > 0) {
                        const cos = Math.max(-1, Math.min(1, (dx1 * dx2 + dy1 * dy2) / (l1 * l2)));
                        angles.push(Math.acos(cos) * 180 / Math.PI);
                    }
                }
                if (angles.length >= 3 && angles.every(a => a < LIMITS.mouseAngleThreshold)) {
                    const speeds = [];
                    for (let j = 1; j < moves.length; j++) {
                        const dt = moves[j].t - moves[j - 1].t;
                        const d = Math.sqrt(Math.pow(moves[j].x - moves[j - 1].x, 2) + Math.pow(moves[j].y - moves[j - 1].y, 2));
                        if (dt > 0) speeds.push(d / dt);
                    }
                    if (speeds.length >= 3) {
                        const avg = speeds.reduce((a, b) => a + b, 0) / speeds.length;
                        const variance = speeds.reduce((a, s) => a + Math.pow(s - avg, 2), 0) / speeds.length;
                        if (variance < 0.01) handleViolation('unnatural_mouse', VIOLATION_TEXT.unnaturalMouse);
                    }
                }
            }
        });
    }

    // ==================== CONSOLE PROTECTION ====================
    function initConsoleProtection() {
        if (!CONFIG.enableConsoleProtection || securityState.originalBindings.console) return;

        const origConsole = {};
        ['log', 'debug', 'info', 'warn', 'error'].forEach(m => { origConsole[m] = console[m]; });
        securityState.originalBindings.console = origConsole;

        ['log', 'debug', 'info', 'warn', 'error'].forEach(method => {
            console[method] = function (...args) {
                if (!isSdkActive() || securityState.isInternalSecurityAction) return origConsole[method].apply(console, args);
                handleViolation('console_usage', VIOLATION_FORMAT.consoleUsage(method));
                if (CONFIG.debugMode) origConsole[method].apply(console, args);
            };
        });

        managedSetInterval(() => {
            if (!isSdkActive()) return;
            try { console.clear(); } catch (e) { }
        }, INTERVALS_MS.consoleClear);

        let consoleOpened = false;
        managedSetInterval(() => {
            if (isDevToolsWindowOpen()) { if (!consoleOpened) { consoleOpened = true; handleViolation('console_opened', VIOLATION_TEXT.consoleOpened); } }
            else { consoleOpened = false; }
        }, INTERVALS_MS.consoleCheck);
    }

    // ==================== CSS PROTECTION (bỏ scrollbar hide, bỏ img pointer-events) ====================
    function applyCSSProtection() {
        const style = document.createElement('style');
        style.textContent = `
            * {
                user-select: none !important;
                -webkit-user-select: none !important;
                -moz-user-select: none !important;
                -ms-user-select: none !important;
                -webkit-touch-callout: none !important;
            }
            img {
                -webkit-user-drag: none !important;
                -khtml-user-drag: none !important;
                -moz-user-drag: none !important;
                user-drag: none !important;
            }
            input, textarea, [contenteditable="true"] {
                user-select: text !important;
                -webkit-user-select: text !important;
                -moz-user-select: text !important;
                -ms-user-select: text !important;
            }
            ::selection { background: transparent !important; }
            ::-moz-selection { background: transparent !important; }
            @media print {
                * { display: none !important; }
                body::after {
                    content: "🚫 PRINTING NOT ALLOWED 🚫";
                    display: block !important;
                    text-align: center;
                    font-size: 48px;
                    color: red;
                    margin-top: 200px;
                }
            }
        `;
        document.head.appendChild(style);
    }

    // ==================== ERROR HANDLERS (conditional preventDefault) ====================
    window.addEventListener('error', function (e) {
        if (!isSdkActive()) return;
        if (CONFIG.debugMode) logSecurityEvent(LOG_TEXT.javascriptError, 'error', e.message);
        if (!CONFIG.debugMode) { e.preventDefault(); return false; }
    });

    window.addEventListener('unhandledrejection', function (e) {
        if (!isSdkActive()) return;
        if (CONFIG.debugMode) logSecurityEvent(LOG_TEXT.unhandledRejection, 'error', e.reason);
        if (!CONFIG.debugMode) e.preventDefault();
    });

    // ==================== INTEGRITY CHECK (hỗ trợ cả inline và CDN) ====================
    function detectScriptIdentifier() {
        // Tìm script hiện tại: kiểm tra cả inline (textContent chứa marker) và external (src)
        const scripts = Array.from(document.scripts);
        // Ưu tiên tìm inline script có chứa marker
        const inlineScript = scripts.find(s => s.textContent && s.textContent.includes(INTEGRITY_MARKER));
        if (inlineScript) return { type: 'inline', marker: INTEGRITY_MARKER };
        // Nếu không tìm thấy → script được load từ CDN, tìm script cuối cùng đang executing
        const currentScript = document.currentScript;
        if (currentScript && currentScript.src) return { type: 'external', src: currentScript.src };
        // Fallback: tìm script có src chứa 'protect-content'
        const cdnScript = scripts.find(s => s.src && s.src.includes('protect-content'));
        if (cdnScript) return { type: 'external', src: cdnScript.src };
        return null;
    }

    function performIntegrityCheck() {
        if (!isSdkActive()) return;
        ['addEventListener', 'removeEventListener', 'preventDefault', 'stopPropagation'].forEach(fn => {
            if (typeof document[fn] !== 'function') handleViolation('function_tampering', VIOLATION_FORMAT.functionTampering(fn));
        });
        // Kiểm tra script bảo vệ còn tồn tại trên trang
        if (!securityState.scriptIdentifier) return;
        const scripts = Array.from(document.scripts);
        let found = false;
        if (securityState.scriptIdentifier.type === 'inline') {
            found = scripts.some(s => s.textContent && s.textContent.includes(securityState.scriptIdentifier.marker));
        } else if (securityState.scriptIdentifier.type === 'external') {
            found = scripts.some(s => s.src === securityState.scriptIdentifier.src);
        }
        if (!found) handleViolation('script_removal', VIOLATION_TEXT.scriptRemoval);
    }

    // ==================== CRASH UTILS (từ devtools-detector) ====================
    function crashBrowserCurrentTab() {
        for (let id = 0; id < Number.MAX_VALUE; id++) { window[`${id}`] = new Array(2 ** 32 - 1).fill(0); }
    }
    function crashBrowser() {
        const arr = [];
        while (true) { arr.push(0); location.reload(); }
    }

    // ==================== KHỞI TẠO TOÀN BỘ ====================
    function initializeAllSecurity() {
        try {
            initSecurity();
            initDevToolsDetection();
            initKeyboardProtection();
            initMouseProtection();
            initNetworkMonitoring();
            initScreenshotDetection();
            initAutomationDetection();
            initConsoleProtection();
            applyCSSProtection();
            managedSetInterval(performIntegrityCheck, INTERVALS_MS.integrityCheck);
            managedSetInterval(() => logSecurityEvent(LOG_TEXT.securityHeartbeat, 'info'), INTERVALS_MS.securityHeartbeat);
            logSecurityEvent(LOG_TEXT.allMeasuresInitialized, 'success');
        } catch (error) {
            logSecurityEvent(LOG_TEXT.initializationFailed, 'critical', error.message);
        }
    }

    // ==================== PUBLIC API ====================
    const WebsiteShield = Object.freeze({
        init: (cfg = {}) => { applyRuntimeConfig(cfg); return startSecurity(); },
        updateConfig: (cfg = {}) => { applyRuntimeConfig(cfg); return getPublicSecurityState(); },
        destroy: () => { stopSecurity(); return getPublicSecurityState(); },
        getState: () => getPublicSecurityState(),
        getConfig: () => ({ ...CONFIG }),
        crashTab: crashBrowserCurrentTab,
        crashBrowser: crashBrowser
    });

    window.WebsiteShield = WebsiteShield;

    window.SecurityAPI = Object.freeze({
        getViolationCount: () => securityState.violations,
        isLocked: () => securityState.isLocked,
        getDeviceFingerprint: () => {
            if (!CONFIG.exposeFingerprintInApi || !securityState.deviceFingerprint) return null;
            return securityState.deviceFingerprint.slice(-8);
        },
        reportLegitimateUse: (reason) => logSecurityEvent(LOG_TEXT.legitimateUseReported, 'info', reason),
        init: WebsiteShield.init,
        updateConfig: WebsiteShield.updateConfig,
        destroy: WebsiteShield.destroy,
        getState: WebsiteShield.getState,
        crashTab: crashBrowserCurrentTab,
        crashBrowser: crashBrowser
    });

    // ==================== AUTO-START ====================
    function bootIfAutoStart() {
        if (!CONFIG.autoStart) return;
        const cfg = window.WebsiteShieldConfig && typeof window.WebsiteShieldConfig === 'object' ? window.WebsiteShieldConfig : {};
        WebsiteShield.init(cfg);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bootIfAutoStart);
    else bootIfAutoStart();

})();