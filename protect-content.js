// Script bảo vệ website toàn diện - triển khai bảo mật nâng cao
(function() {
    'use strict';

    // Cấu hình hệ thống bảo vệ
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
        lockoutTime: 300000, // 5 phút
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
        maxReasonLength: 200
    };

    const INTERVALS_MS = {
        devToolsSizeCheck: 100,
        devToolsConsoleCheck: 1000,
        devToolsDebuggerCheck: 3000,
        rapidClickWindow: 1000,
        consoleClear: 1000,
        consoleCheck: 100,
        integrityCheck: 5000,
        securityHeartbeat: 30000
    };

    // STATE: Quản lý trạng thái bảo mật trong phiên hiện tại
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
        originalBindings: {
            fetch: null,
            xhrOpen: null,
            webSocket: null,
            console: null,
            functionToString: null
        },
        runtimeIntervals: []
    };
    let contentInteractionProtectionInitialized = false;

    // TEXT + HELPERS: Cấu hình văn bản hiển thị và thông điệp hệ thống
    const STORAGE_KEYS = {
        flaggedDevices: 'flagged_devices',
        securityEvents: 'security_events'
    };
    const SECURITY_TEXT = {
        violation: {
            copyAttempt: 'Content copy attempted',
            cutAttempt: 'Content cut attempted',
            pasteAttempt: 'Paste attempted',
            dragBlocked: 'Drag operation blocked',
            devtoolsSize: 'Window size indicates DevTools',
            devtoolsConsole: 'Console access detected',
            devtoolsDebugger: 'Debugger statement delay detected',
            devtoolsOverride: 'Console function override detected',
            printScreen: 'Print Screen key detected',
            unnaturalMouse: 'Linear mouse movement detected',
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
        error: {
            devtoolsDetected: 'DevTools detected'
        }
    };
    const VIOLATION_FORMAT = {
        suspiciousPattern: (pattern, timeDiff) => `Pattern: ${pattern.join(',')} | Time: ${timeDiff}ms`,
        rapidClicking: (clickCount) => `${clickCount} clicks in 1 second`,
        potentialScreenshotHidden: (hiddenTime) => `Hidden for ${hiddenTime}ms`,
        potentialScreenshotFocus: (blurTime) => `Focus lost for ${blurTime}ms`,
        automationDetected: (count) => `${count} indicators found`,
        consoleUsage: (method) => `Console.${method} called`,
        functionTampering: (funcName) => `${funcName} has been modified`
    };
    const VIOLATION_TEXT = SECURITY_TEXT.violation;
    const LOG_TEXT = SECURITY_TEXT.log;
    const ERROR_TEXT = SECURITY_TEXT.error;

    function isEditableTarget(target) {
        return target.tagName === 'INPUT' ||
            target.tagName === 'TEXTAREA' ||
            target.contentEditable === 'true';
    }

    function isEnforceMode() {
        return CONFIG.mode !== 'monitor';
    }

    function isSdkActive() {
        return securityState.sdkActive;
    }

    function managedSetInterval(callback, intervalMs) {
        const intervalId = setInterval(callback, intervalMs);
        securityState.runtimeIntervals.push(intervalId);
        return intervalId;
    }

    function clearManagedIntervals() {
        securityState.runtimeIntervals.forEach(intervalId => clearInterval(intervalId));
        securityState.runtimeIntervals = [];
    }

    function applyRuntimeConfig(overrides = {}) {
        if (!overrides || typeof overrides !== 'object') {
            return;
        }

        const allowedKeys = Object.keys(CONFIG);
        allowedKeys.forEach(key => {
            if (Object.prototype.hasOwnProperty.call(overrides, key)) {
                CONFIG[key] = overrides[key];
            }
        });

        if (CONFIG.mode !== 'enforce' && CONFIG.mode !== 'monitor') {
            CONFIG.mode = 'enforce';
        }
    }

    function restoreOriginalBindings() {
        if (securityState.originalBindings.fetch) {
            window.fetch = securityState.originalBindings.fetch;
        }

        if (securityState.originalBindings.xhrOpen) {
            window.XMLHttpRequest.prototype.open = securityState.originalBindings.xhrOpen;
        }

        if (securityState.originalBindings.webSocket) {
            window.WebSocket = securityState.originalBindings.webSocket;
        }

        if (securityState.originalBindings.console) {
            ['log', 'debug', 'info', 'warn', 'error'].forEach(method => {
                if (securityState.originalBindings.console[method]) {
                    console[method] = securityState.originalBindings.console[method];
                }
            });
        }

        if (securityState.originalBindings.functionToString) {
            Function.prototype.toString = securityState.originalBindings.functionToString;
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

        securityState.originalBindings = {
            fetch: null,
            xhrOpen: null,
            webSocket: null,
            console: null,
            functionToString: null
        };

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
        } catch (error) {
            const fallback = String(value);
            return fallback.length > maxLength ? `${fallback.slice(0, maxLength)}...` : fallback;
        }
    }

    function isTelemetryRequest(requestInput) {
        if (!CONFIG.telemetryEndpoint) return false;

        try {
            const inputUrl = typeof requestInput === 'string' ? requestInput : requestInput?.url;
            if (!inputUrl) return false;

            const targetUrl = new URL(inputUrl, window.location.href).href;
            const telemetryUrl = new URL(CONFIG.telemetryEndpoint, window.location.href).href;
            return targetUrl === telemetryUrl;
        } catch (error) {
            return false;
        }
    }

    function getPersistentStorageKey(key) {
        return `security:${key}`;
    }

    function renderLockdownOverlay(reason) {
        const existingOverlay = document.getElementById('security-lockdown-overlay');
        if (existingOverlay) {
            existingOverlay.remove();
        }

        const overlay = document.createElement('div');
        overlay.id = 'security-lockdown-overlay';
        overlay.style.cssText = `
            position: fixed;
            inset: 0;
            z-index: 2147483647;
            background: rgba(0, 0, 0, 0.92);
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 24px;
        `;

        const reasonText = toSafeString(reason, LIMITS.maxReasonLength);
        overlay.innerHTML = `
            <div>
                <h1 style="font-size: 28px; margin-bottom: 12px;">Access temporarily restricted</h1>
                <p style="font-size: 16px; margin-bottom: 8px;">Website is protected</p>
                <p style="font-size: 14px; opacity: 0.8;">Reason: ${reasonText}</p>
            </div>
        `;

        document.body.appendChild(overlay);
    }

    function clearLockdownOverlay() {
        const overlay = document.getElementById('security-lockdown-overlay');
        if (overlay) {
            overlay.remove();
        }
    }

    function reportSecurityEventToServer(event) {
        if (!CONFIG.telemetryEndpoint || securityState.isInternalSecurityAction) {
            return;
        }

        try {
            securityState.isInternalSecurityAction = true;

            const payload = JSON.stringify({
                ...event,
                page: window.location.href
            });

            if (navigator.sendBeacon) {
                const blob = new Blob([payload], { type: 'application/json' });
                navigator.sendBeacon(CONFIG.telemetryEndpoint, blob);
            } else {
                fetch(CONFIG.telemetryEndpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...(CONFIG.telemetryAuthToken ? { 'Authorization': `Bearer ${CONFIG.telemetryAuthToken}` } : {})
                    },
                    body: payload,
                    keepalive: true,
                    credentials: 'omit'
                }).catch(() => {});
            }
        } catch (error) {
            // Bỏ qua lỗi telemetry để không ảnh hưởng luồng chính
        } finally {
            securityState.isInternalSecurityAction = false;
        }
    }

    // Tạo dấu vân tay thiết bị để nhận diện phiên truy cập
    function generateFingerprint() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Device fingerprint', 2, 2);
        
        return btoa(JSON.stringify({
            screen: `${screen.width}x${screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            platform: navigator.platform,
            canvas: canvas.toDataURL(),
            webgl: getWebGLFingerprint(),
            plugins: Array.from(navigator.plugins).map(p => p.name).join(','),
            userAgent: navigator.userAgent.slice(0, 100)
        }));
    }

    function getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return 'no-webgl';
            
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            return debugInfo ? 
                gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 
                'webgl-available';
        } catch(e) {
            return 'webgl-error';
        }
    }

    // Khởi tạo bảo mật ban đầu
    function initSecurity() {
        securityState.deviceFingerprint = generateFingerprint();

        if (!CONFIG.enableLockdown) {
            logSecurityEvent(LOG_TEXT.securityInitialized, 'info');
            return;
        }
        
        // Kiểm tra thiết bị đã nằm trong danh sách bị đánh dấu hay chưa
        const flaggedDevices = getStoredData(STORAGE_KEYS.flaggedDevices) || [];
        if (flaggedDevices.includes(securityState.deviceFingerprint)) {
            triggerLockdown('Device flagged');
            return;
        }

        logSecurityEvent(LOG_TEXT.securityInitialized, 'info');
    }

    function handleViolation(type, details = null) {
        if (!isSdkActive() || securityState.isLocked) {
            return;
        }

        securityState.violations += 1;
        securityState.lastViolation = Date.now();

        const activityRecord = {
            type,
            details: toSafeString(details),
            timestamp: Date.now(),
            fingerprint: securityState.deviceFingerprint
        };

        securityState.suspiciousActivity.push(activityRecord);
        if (securityState.suspiciousActivity.length > LIMITS.maxSuspiciousActivities) {
            securityState.suspiciousActivity.shift();
        }

        logSecurityEvent(LOG_TEXT.violationDetected(type), 'warning', activityRecord.details);

        if (CONFIG.enableLockdown && securityState.violations >= CONFIG.maxViolations) {
            triggerLockdown(`Multiple violations (${securityState.violations})`);
        }
    }

    function triggerLockdown(reason) {
        if (!CONFIG.enableLockdown) {
            return;
        }

        if (securityState.isLocked) {
            return;
        }

        securityState.isLocked = true;

        const safeReason = toSafeString(reason, LIMITS.maxReasonLength);
        const flaggedDevices = getStoredData(STORAGE_KEYS.flaggedDevices) || [];
        if (!flaggedDevices.includes(securityState.deviceFingerprint)) {
            flaggedDevices.push(securityState.deviceFingerprint);
            storeData(STORAGE_KEYS.flaggedDevices, flaggedDevices);
        }

        logSecurityEvent(LOG_TEXT.lockdownTriggered(safeReason), 'critical');
        renderLockdownOverlay(safeReason);

        if (securityState.lockdownTimer) {
            clearTimeout(securityState.lockdownTimer);
        }

        securityState.lockdownTimer = setTimeout(() => {
            securityState.isLocked = false;
            securityState.violations = 0;
            clearLockdownOverlay();
            logSecurityEvent(LOG_TEXT.lockdownReleased, 'info');
        }, CONFIG.lockoutTime);
    }

    // Kiểm tra DevTools qua chênh lệch kích thước cửa sổ
    function isDevToolsWindowOpen(threshold = LIMITS.devToolsWindowThreshold) {
        return (
            window.outerHeight - window.innerHeight > threshold ||
            window.outerWidth - window.innerWidth > threshold
        );
    }

    // Đăng ký một lần các lớp chặn tương tác nội dung dùng chung
    function initContentInteractionProtection() {
        if (contentInteractionProtectionInitialized) return;
        contentInteractionProtectionInitialized = true;

        // Vô hiệu hóa sự kiện sao chép / dán / cắt
        ['copy', 'paste', 'cut'].forEach(eventType => {
            document.addEventListener(eventType, function(e) {
                if (!isSdkActive()) {
                    return true;
                }

                if (!isEnforceMode()) {
                    if (eventType === 'copy') {
                        handleViolation('copy_attempt', VIOLATION_TEXT.copyAttempt);
                    } else if (eventType === 'cut') {
                        handleViolation('cut_attempt', VIOLATION_TEXT.cutAttempt);
                    } else if (eventType === 'paste') {
                        handleViolation('paste_attempt', VIOLATION_TEXT.pasteAttempt);
                    }
                    return true;
                }

                e.preventDefault();
                e.stopPropagation();

                if (eventType === 'copy') {
                    e.clipboardData?.setData('text/plain', '');
                    handleViolation('copy_attempt', VIOLATION_TEXT.copyAttempt);
                } else if (eventType === 'cut') {
                    handleViolation('cut_attempt', VIOLATION_TEXT.cutAttempt);
                } else if (eventType === 'paste') {
                    handleViolation('paste_attempt', VIOLATION_TEXT.pasteAttempt);
                }

                return false;
            });
        });

        // Vô hiệu hóa chọn văn bản
        document.addEventListener('selectstart', function(e) {
            if (!isSdkActive() || !isEnforceMode()) {
                return true;
            }

            // Vẫn cho phép chọn nội dung trong ô nhập liệu
            if (isEditableTarget(e.target)) {
                return true;
            }

            e.preventDefault();
            return false;
        });

        // Vô hiệu hóa thao tác kéo thả
        ['dragstart', 'drag', 'dragend', 'dragover', 'dragenter', 'dragleave', 'drop'].forEach(eventType => {
            document.addEventListener(eventType, function(e) {
                if (!isSdkActive()) {
                    return true;
                }

                if (!isEnforceMode()) {
                    if (eventType === 'dragstart') {
                        handleViolation('drag_attempt', VIOLATION_TEXT.dragBlocked);
                    }
                    return true;
                }

                e.preventDefault();
                e.stopPropagation();

                if (eventType === 'dragstart') {
                    handleViolation('drag_attempt', VIOLATION_TEXT.dragBlocked);
                }

                return false;
            });
        });
    }

    // Phát hiện DevTools nâng cao
    function initDevToolsDetection() {
        if (!CONFIG.enableDevToolsDetection) return;

        let devToolsOpen = false;
        const threshold = LIMITS.devToolsWindowThreshold;

        // Cách 1: Phát hiện qua chênh lệch kích thước cửa sổ
        managedSetInterval(() => {
            if (!isSdkActive()) return;
            const isOpen = isDevToolsWindowOpen(threshold);
            
            if (isOpen && !devToolsOpen) {
                devToolsOpen = true;
                handleViolation('devtools_size', VIOLATION_TEXT.devtoolsSize);
            } else if (!isOpen && devToolsOpen) {
                devToolsOpen = false;
            }
        }, INTERVALS_MS.devToolsSizeCheck);

        // Cách 2: Phát hiện qua truy cập console
        let consoleElement = new Image();
        Object.defineProperty(consoleElement, 'id', {
            get: function() {
                handleViolation('devtools_console', VIOLATION_TEXT.devtoolsConsole);
                throw new Error(ERROR_TEXT.devtoolsDetected);
            }
        });

        managedSetInterval(() => {
            if (!isSdkActive()) return;
            try {
                console.log(consoleElement);
                console.clear();
            } catch(e) {
                // Đã phát hiện DevTools
            }
        }, INTERVALS_MS.devToolsConsoleCheck);

        // Cách 3: Phát hiện qua độ trễ khi dừng debugger
        managedSetInterval(() => {
            if (!isSdkActive()) return;
            const start = performance.now();
            debugger;
            const end = performance.now();
            
            if (end - start > LIMITS.debuggerDelayThresholdMs) {
                handleViolation('devtools_debugger', VIOLATION_TEXT.devtoolsDebugger);
            }
        }, INTERVALS_MS.devToolsDebuggerCheck);

        // Cách 4: Theo dõi hành vi ghi đè hàm toString
        if (securityState.originalBindings.functionToString) {
            return;
        }

        securityState.originalBindings.functionToString = Function.prototype.toString;
        Function.prototype.toString = function() {
            if (this === console.log || this === console.clear || this === console.dir) {
                handleViolation('devtools_override', VIOLATION_TEXT.devtoolsOverride);
            }
            return securityState.originalBindings.functionToString.call(this);
        };
    }

    // Bảo vệ bàn phím nâng cao
    function initKeyboardProtection() {
        if (!CONFIG.enableKeyboardProtection) return;
        
        const blockedKeys = [
            // Nhóm phím chức năng
            { key: 123 }, // F12
            { key: 116 }, // F5
            { key: 117 }, // F6
            { key: 118 }, // F7
            { key: 119 }, // F8
            { key: 120 }, // F9
            { key: 121 }, // F10
            { key: 122 }, // F11
            
            // Tổ hợp mở công cụ lập trình
            { ctrl: true, shift: true, key: 73 }, // Ctrl+Shift+I
            { ctrl: true, shift: true, key: 74 }, // Ctrl+Shift+J
            { ctrl: true, shift: true, key: 67 }, // Ctrl+Shift+C
            { ctrl: true, shift: true, key: 75 }, // Ctrl+Shift+K (Bảng điều khiển Firefox)
            { ctrl: true, shift: true, key: 69 }, // Ctrl+Shift+E (Tab mạng trên Firefox)
            
            // Tổ hợp phím tắt của trình duyệt
            { ctrl: true, key: 85 }, // Ctrl+U (Xem mã nguồn)
            { ctrl: true, key: 83 }, // Ctrl+S (Lưu trang)
            { ctrl: true, key: 65 }, // Ctrl+A (Chọn tất cả)
            { ctrl: true, key: 80 }, // Ctrl+P (In trang)
            { ctrl: true, key: 72 }, // Ctrl+H (Lịch sử)
            { ctrl: true, key: 68 }, // Ctrl+D (Đánh dấu trang)
            { ctrl: true, key: 70 }, // Ctrl+F (Tìm kiếm)
            { ctrl: true, key: 82 }, // Ctrl+R (Tải lại)
            { ctrl: true, key: 78 }, // Ctrl+N (Cửa sổ mới)
            { ctrl: true, key: 84 }, // Ctrl+T (Tab mới)
            { ctrl: true, key: 87 }, // Ctrl+W (Đóng tab)
            
            // Tổ hợp chụp màn hình - Windows
            { key: 44 }, // Print Screen (PrtSc)
            { key: 44, alt: true }, // Alt+PrtSc
            { key: 44, win: true }, // Windows+PrtSc
            { key: 71, win: true }, // Windows+G (Chụp màn hình qua Game Bar)
            
            // Tổ hợp chụp màn hình - Mac
            { key: 51, cmd: true }, // Command+3 (Chụp màn hình trên Mac)
            { key: 52, cmd: true }, // Command+4 (Chụp vùng màn hình trên Mac)
            { key: 51, cmd: true, shift: true }, // Command+Shift+3 (Chụp toàn màn hình)
            { key: 52, cmd: true, shift: true }, // Command+Shift+4 (Chụp một phần màn hình)
            { key: 53, cmd: true, shift: true }, // Command+Shift+5 (Mở công cụ chụp màn hình)
            
            // Tổ hợp mở DevTools trên Safari (Mac)
            { key: 73, cmd: true, alt: true }, // Cmd+Alt+I
            { key: 67, cmd: true, alt: true }, // Cmd+Alt+C
            { key: 74, cmd: true, alt: true }, // Cmd+Alt+J
        ];
    
        // Bộ xử lý sự kiện bàn phím nâng cao
        document.addEventListener('keydown', function(e) {
            if (!isSdkActive()) {
                return true;
            }

            // Nhận diện các phím bổ trợ (Ctrl/Shift/Alt/Win/Cmd)
            const isWinKey = e.key === 'Meta' || e.metaKey || e.key === 'OS' || 
                            e.keyCode === 91 || e.keyCode === 92 || e.which === 91 || e.which === 92;
            
            const isCmdKey = e.metaKey || e.key === 'Meta' || e.keyCode === 91 || e.keyCode === 93;
            
            // Kiểm tra tổ hợp phím có nằm trong danh sách chặn hay không
            const blocked = blockedKeys.some(combo => {
                const keyMatch = combo.key === e.keyCode || combo.key === e.which;
                const ctrlMatch = !combo.ctrl || e.ctrlKey;
                const shiftMatch = !combo.shift || e.shiftKey;
                const altMatch = !combo.alt || e.altKey;
                const winMatch = !combo.win || isWinKey;
                const cmdMatch = !combo.cmd || isCmdKey;
                
                return keyMatch && ctrlMatch && shiftMatch && altMatch && winMatch && cmdMatch;
            });
    
            // Các nhận diện bổ sung cho trường hợp đặc biệt
            const isPrintScreen = 
                e.key === 'PrintScreen' || 
                e.code === 'PrintScreen' ||
                e.keyCode === 44 || 
                e.which === 44;
    
            const isGameBar = 
                (isWinKey && (e.keyCode === 71 || e.key === 'G' || e.key === 'g'));
    
            const isMacScreenshot = 
                (isCmdKey && (e.keyCode === 51 || e.keyCode === 52 || e.keyCode === 53)) ||
                (isCmdKey && e.shiftKey && (e.keyCode === 51 || e.keyCode === 52 || e.keyCode === 53));
    
            // Phím mở menu ngữ cảnh
            const isContextMenu = e.keyCode === 93 || e.key === 'ContextMenu';
    
            // Chặn sự kiện nếu khớp bất kỳ tiêu chí nào
            if (blocked || isPrintScreen || isGameBar || isMacScreenshot || isContextMenu) {
                if (!isEnforceMode()) {
                    let violationType = 'blocked_shortcut';
                    if (isPrintScreen || isGameBar || isMacScreenshot) {
                        violationType = 'screenshot_attempt';
                    } else if (isContextMenu) {
                        violationType = 'context_menu_blocked';
                    }
                    handleViolation(violationType, `Key combination: ${e.keyCode}`);
                    return true;
                }

                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                
                // Xác định loại vi phạm và nội dung cảnh báo tương ứng
                let violationType = 'blocked_shortcut';
                
                if (isPrintScreen || isGameBar || isMacScreenshot) {
                    violationType = 'screenshot_attempt';
                } else if (isContextMenu) {
                    violationType = 'context_menu_blocked';
                }
                
                // Ghi nhận vi phạm để phục vụ theo dõi
                handleViolation(violationType, `Key combination: ${e.keyCode}`);
                
                // Biện pháp chặn bổ sung cho một số trình duyệt cũ
                if (typeof e.returnValue !== 'undefined') {
                    e.returnValue = false;
                }
                
                return false;
            }
        }, true);
    
        // Phát hiện chuỗi phím đáng ngờ (nâng cao)
        let keySequence = [];
        let keyTimestamps = [];
        
        document.addEventListener('keydown', function(e) {
            if (!isSdkActive()) {
                return;
            }

            const currentTime = Date.now();
            
            // Xóa dữ liệu phím cũ (quá 2 giây)
            const cutoffTime = currentTime - LIMITS.keySequenceWindowMs;
            while (keyTimestamps.length > 0 && keyTimestamps[0] < cutoffTime) {
                keySequence.shift();
                keyTimestamps.shift();
            }
            
            // Thêm phím hiện tại vào chuỗi theo dõi
            keySequence.push(e.keyCode);
            keyTimestamps.push(currentTime);
            
            // Giới hạn độ dài chuỗi để tránh tăng bộ nhớ
            if (keySequence.length > LIMITS.maxKeySequenceLength) {
                keySequence.shift();
                keyTimestamps.shift();
            }
    
            // Khai báo các mẫu chuỗi phím đáng ngờ (thường dùng để mở DevTools)
            const suspiciousPatterns = [
                [17, 85], // Ctrl+U
                [17, 16, 73], // Ctrl+Shift+I
                [17, 16, 74], // Ctrl+Shift+J
                [17, 16, 67], // Ctrl+Shift+C
                [17, 16, 75], // Ctrl+Shift+K
                [123], // F12
                [44], // Print Screen
                [91, 71], // Win+G
                [92, 71], // Win+G (mã phím Windows thay thế)
                [91, 51], // Cmd+3
                [91, 52], // Cmd+4
                [91, 16, 51], // Cmd+Shift+3
                [91, 16, 52], // Cmd+Shift+4
                [91, 16, 53], // Cmd+Shift+5
            ];
    
            // Đối chiếu với các mẫu đáng ngờ
            suspiciousPatterns.forEach(pattern => {
                if (keySequence.length >= pattern.length) {
                    const recentKeys = keySequence.slice(-pattern.length);
                    
                    if (recentKeys.every((key, i) => key === pattern[i])) {
                        const recentTimes = keyTimestamps.slice(-pattern.length);
                        const timeDiff = recentTimes[recentTimes.length - 1] - recentTimes[0];

                        handleViolation('suspicious_key_pattern', VIOLATION_FORMAT.suspiciousPattern(pattern, timeDiff));
                    }
                }
            });
        });

        // Kích hoạt lớp chặn tương tác nội dung dùng chung
        initContentInteractionProtection();
    }

    // Bảo vệ chuột nâng cao
    function initMouseProtection() {
        if (!CONFIG.enableMouseProtection) return;

        // Chặn chuột phải và chuyển thành hành vi chuột trái
        document.addEventListener('contextmenu', function(e) {
            if (!isSdkActive()) {
                return true;
            }

            if (!isEnforceMode()) {
                handleViolation('context_menu_blocked', 'Context menu usage detected');
                return true;
            }

            e.preventDefault();
            
            // Tạo sự kiện click trái thay thế
            const leftClick = new MouseEvent('click', {
                bubbles: true,
                cancelable: true,
                clientX: e.clientX,
                clientY: e.clientY,
                button: 0,
                buttons: 1
            });
            
            e.target.dispatchEvent(leftClick);
            return false;
        });

        // Phát hiện click quá nhanh (nghi ngờ tự động hóa)
        let clickCount = 0;
        let clickTimer = null;

        document.addEventListener('click', function(e) {
            if (!isSdkActive()) {
                return;
            }

            clickCount++;
            
            if (clickTimer) clearTimeout(clickTimer);
            
            clickTimer = setTimeout(() => {
                if (clickCount > LIMITS.rapidClicksPerWindow) {
                    handleViolation('rapid_clicking', VIOLATION_FORMAT.rapidClicking(clickCount));
                }
                clickCount = 0;
            }, INTERVALS_MS.rapidClickWindow);
        });

        // Kích hoạt lớp chặn tương tác nội dung dùng chung
        initContentInteractionProtection();
    }

    // Giám sát hoạt động mạng
    function initNetworkMonitoring() {
        if (!CONFIG.enableNetworkMonitoring) return;

        if (securityState.originalBindings.fetch) return;

        // Theo dõi các request qua fetch
        const originalFetch = window.fetch;
        securityState.originalBindings.fetch = originalFetch;
        window.fetch = function(...args) {
            if (!securityState.isInternalSecurityAction && !isTelemetryRequest(args[0])) {
                logSecurityEvent(LOG_TEXT.networkRequestDetected, 'info', toSafeString(args[0]));
            }
            return originalFetch.apply(this, args);
        };

        // Theo dõi các request qua XMLHttpRequest
        const originalXHR = window.XMLHttpRequest.prototype.open;
        securityState.originalBindings.xhrOpen = originalXHR;
        window.XMLHttpRequest.prototype.open = function(method, url) {
            if (!securityState.isInternalSecurityAction && !isTelemetryRequest(url)) {
                logSecurityEvent(LOG_TEXT.xhrRequestDetected, 'info', `${method} ${url}`);
            }
            return originalXHR.apply(this, arguments);
        };

        // Theo dõi kết nối WebSocket
        const originalWebSocket = window.WebSocket;
        securityState.originalBindings.webSocket = originalWebSocket;
        const WrappedWebSocket = function(url, protocols) {
            if (!securityState.isInternalSecurityAction) {
                logSecurityEvent(LOG_TEXT.websocketDetected, 'warning', toSafeString(url));
            }
            return protocols !== undefined ? new originalWebSocket(url, protocols) : new originalWebSocket(url);
        };
        WrappedWebSocket.prototype = originalWebSocket.prototype;
        Object.setPrototypeOf(WrappedWebSocket, originalWebSocket);
        window.WebSocket = WrappedWebSocket;
    }

    // Phát hiện hành vi chụp màn hình
    function initScreenshotDetection() {
        if (!CONFIG.enableScreenshotDetection) return;

        // Cách 1: Phát hiện qua thay đổi trạng thái hiển thị tab
        let visibilityTimer = null;
        document.addEventListener('visibilitychange', function() {
            if (!isSdkActive()) {
                return;
            }

            if (document.hidden) {
                visibilityTimer = Date.now();
            } else if (visibilityTimer) {
                const hiddenTime = Date.now() - visibilityTimer;
                if (hiddenTime < LIMITS.screenshotHiddenMaxMs && hiddenTime > LIMITS.screenshotHiddenMinMs) {
                    handleViolation('potential_screenshot', VIOLATION_FORMAT.potentialScreenshotHidden(hiddenTime));
                }
                visibilityTimer = null;
            }
        });

        // Cách 2: Phát hiện qua sự kiện mất/nhận focus
        let focusLossTime = null;
        window.addEventListener('blur', function() {
            if (!isSdkActive()) {
                return;
            }
            focusLossTime = Date.now();
            document.body.style.filter = 'blur(10px)';
        });

        window.addEventListener('focus', function() {
            if (!isSdkActive()) {
                return;
            }
            document.body.style.filter = 'none';
            if (focusLossTime) {
                const blurTime = Date.now() - focusLossTime;
                if (blurTime < LIMITS.screenshotFocusMaxMs && blurTime > LIMITS.screenshotFocusMinMs) {
                    handleViolation('potential_screenshot', VIOLATION_FORMAT.potentialScreenshotFocus(blurTime));
                }
                focusLossTime = null;
            }
        });

        // Cách 3: Phát hiện phím Print Screen
        document.addEventListener('keyup', function(e) {
            if (!isSdkActive()) {
                return;
            }
            if (e.keyCode === 44 || e.key === 'PrintScreen') {
                handleViolation('print_screen', VIOLATION_TEXT.printScreen);
            }
        });
    }

    // Phát hiện công cụ tự động hóa
    function initAutomationDetection() {
        // Nhận diện trình duyệt headless và dấu hiệu automation
        const automationIndicators = [
            () => navigator.webdriver,
            () => window.phantom || window.callPhantom,
            () => window.Buffer,
            () => window.emit,
            () => window.spawn,
            () => navigator.userAgent.includes('HeadlessChrome'),
            () => navigator.userAgent.includes('PhantomJS'),
            () => navigator.plugins.length === 0,
            () => navigator.languages.length === 0,
            () => !window.chrome && /Chrome/.test(navigator.userAgent)
        ];

        const detectedIndicators = automationIndicators.filter(check => {
            try {
                return check();
            } catch(e) {
                return false;
            }
        });

        if (detectedIndicators.length > 0) {
            handleViolation('automation_detected', VIOLATION_FORMAT.automationDetected(detectedIndicators.length));
        }

        // Theo dõi quỹ đạo di chuyển chuột
        let mouseMovements = [];
        document.addEventListener('mousemove', function(e) {
            if (!isSdkActive()) {
                return;
            }
            mouseMovements.push({ x: e.clientX, y: e.clientY, time: Date.now() });
            if (mouseMovements.length > LIMITS.maxMouseMovementSamples) mouseMovements.shift();

            // Kiểm tra các mẫu di chuyển bất thường
            if (mouseMovements.length >= 5) {
                const isLinear = mouseMovements.every((point, i) => {
                    if (i === 0) return true;
                    const prev = mouseMovements[i-1];
                    return Math.abs(point.x - prev.x) < 2 && Math.abs(point.y - prev.y) < 2;
                });

                if (isLinear) {
                    handleViolation('unnatural_mouse', VIOLATION_TEXT.unnaturalMouse);
                }
            }
        });
    }

    // Bảo vệ console
    function initConsoleProtection() {
        if (!CONFIG.enableConsoleProtection) return;

        if (securityState.originalBindings.console) return;

        // Ghi đè các hàm console để kiểm soát truy cập
        const originalConsole = { ...console };
        securityState.originalBindings.console = originalConsole;
        
        ['log', 'debug', 'info', 'warn', 'error'].forEach(method => {
            console[method] = function(...args) {
                if (!isSdkActive()) {
                    return originalConsole[method].apply(console, args);
                }

                if (securityState.isInternalSecurityAction) {
                    return originalConsole[method].apply(console, args);
                }

                handleViolation('console_usage', VIOLATION_FORMAT.consoleUsage(method));
                if (CONFIG.debugMode) {
                    originalConsole[method].apply(console, args);
                }
            };
        });

        // Xóa console theo chu kỳ
        managedSetInterval(() => {
            if (!isSdkActive()) return;
            try {
                console.clear();
            } catch(e) {}
        }, INTERVALS_MS.consoleClear);

        // Phát hiện khi bảng console được mở
        let consoleOpened = false;
        const checkConsole = () => {
            const threshold = LIMITS.devToolsWindowThreshold;
            if (isDevToolsWindowOpen(threshold)) {
                if (!consoleOpened) {
                    consoleOpened = true;
                    handleViolation('console_opened', VIOLATION_TEXT.consoleOpened);
                }
            } else {
                consoleOpened = false;
            }
        };

        managedSetInterval(checkConsole, INTERVALS_MS.consoleCheck);
    }

    // Hàm lưu trữ dữ liệu (dùng localStorage đã được làm rối khóa)
    function storeData(key, data) {
        try {
            const storageKey = getPersistentStorageKey(key);
            const payload = {
                version: 1,
                timestamp: Date.now(),
                data
            };
            localStorage.setItem(storageKey, btoa(JSON.stringify(payload)));
        } catch(e) {
            // Lưu dữ liệu thất bại
        }
    }

    function getLegacyStoredData(key) {
        try {
            const keys = Object.keys(localStorage);
            const matchingKey = keys.find(k => {
                try {
                    return atob(k).startsWith(key + '_security_');
                } catch(e) {
                    return false;
                }
            });

            if (!matchingKey) return null;
            const raw = localStorage.getItem(matchingKey);
            if (!raw) return null;
            return JSON.parse(atob(raw));
        } catch (error) {
            return null;
        }
    }

    function getStoredData(key) {
        try {
            const storageKey = getPersistentStorageKey(key);
            const encodedPayload = localStorage.getItem(storageKey);

            if (encodedPayload) {
                const decodedPayload = JSON.parse(atob(encodedPayload));
                if (decodedPayload && typeof decodedPayload === 'object' && 'data' in decodedPayload) {
                    return decodedPayload.data;
                }
                return decodedPayload;
            }

            const legacyData = getLegacyStoredData(key);
            if (legacyData !== null) {
                storeData(key, legacyData);
                return legacyData;
            }
        } catch(e) {
            // Đọc dữ liệu thất bại
        }
        return null;
    }

    // Ghi log bảo mật nâng cao
    function logSecurityEvent(message, level = 'info', details = null) {
        const event = {
            timestamp: new Date().toISOString(),
            level,
            message,
            details: details ? toSafeString(details) : null,
            fingerprint: securityState.deviceFingerprint,
            violations: securityState.violations,
            sessionTime: Date.now() - securityState.sessionStart
        };

        if (CONFIG.debugMode && securityState.originalBindings.console?.log) {
            securityState.originalBindings.console.log('Security Event:', event);
        }

        reportSecurityEventToServer(event);

        // Lưu sự kiện để phục vụ phân tích
        const events = getStoredData(STORAGE_KEYS.securityEvents) || [];
        events.push(event);
        if (events.length > LIMITS.maxStoredSecurityEvents) events.shift(); // Chỉ giữ 100 sự kiện gần nhất
        storeData(STORAGE_KEYS.securityEvents, events);
    }

    // Áp dụng lớp CSS bảo vệ toàn diện
    function applyCSSProtection() {
        const protectionStyles = document.createElement('style');
        protectionStyles.innerHTML = `
            /* Chặn toàn diện thao tác chọn và tương tác */
            * {
                user-select: none !important;
                -webkit-user-select: none !important;
                -moz-user-select: none !important;
                -ms-user-select: none !important;
                -webkit-touch-callout: none !important;
                -webkit-user-drag: none !important;
                -khtml-user-drag: none !important;
                -moz-user-drag: none !important;
                -o-user-drag: none !important;
                user-drag: none !important;
            }
            
            /* Bảo vệ hình ảnh khỏi thao tác kéo/chọn */
            img {
                pointer-events: none !important;
                -webkit-user-drag: none !important;
                -khtml-user-drag: none !important;
                -moz-user-drag: none !important;
                -o-user-drag: none !important;
                user-drag: none !important;
            }
            
            /* Ẩn thanh cuộn */
            ::-webkit-scrollbar { display: none !important; }
            
            /* Tắt highlight khi chọn văn bản */
            ::selection { background: transparent !important; }
            ::-moz-selection { background: transparent !important; }
            
            /* Vô hiệu hóa in trang */
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
            
            /* Tắt hiệu ứng highlight của công cụ inspect */
            *:hover {
                outline: none !important;
                box-shadow: none !important;
            }
        `;
        document.head.appendChild(protectionStyles);
    }

    // Xử lý lỗi và cơ chế phục hồi
    window.addEventListener('error', function(e) {
        if (!isSdkActive()) {
            return;
        }
        if (CONFIG.debugMode) {
            logSecurityEvent(LOG_TEXT.javascriptError, 'error', e.message);
        }
        e.preventDefault();
        return false;
    });

    window.addEventListener('unhandledrejection', function(e) {
        if (!isSdkActive()) {
            return;
        }
        if (CONFIG.debugMode) {
            logSecurityEvent(LOG_TEXT.unhandledRejection, 'error', e.reason);
        }
        e.preventDefault();
    });

    // Kiểm tra tính toàn vẹn của hệ thống bảo vệ
    function performIntegrityCheck() {
        if (!isSdkActive()) {
            return;
        }

        // Kiểm tra các hàm quan trọng có bị can thiệp trái phép không
        const criticalFunctions = [
            'addEventListener',
            'removeEventListener',
            'preventDefault',
            'stopPropagation'
        ];

        criticalFunctions.forEach(funcName => {
            if (typeof document[funcName] !== 'function') {
                handleViolation('function_tampering', VIOLATION_FORMAT.functionTampering(funcName));
            }
        });

        // Kiểm tra script bảo vệ còn tồn tại trên trang hay không
        const scripts = Array.from(document.scripts);
        const securityScript = scripts.find(script => 
            script.textContent && script.textContent.includes('Ultimate Website Protection')
        );

        if (!securityScript) {
            handleViolation('script_removal', VIOLATION_TEXT.scriptRemoval);
        }
    }

    // Khởi tạo toàn bộ cơ chế bảo mật
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

            // Chạy kiểm tra toàn vẹn theo chu kỳ
            managedSetInterval(performIntegrityCheck, INTERVALS_MS.integrityCheck);

            // Gửi heartbeat để đảm bảo script vẫn hoạt động
            managedSetInterval(() => {
                logSecurityEvent(LOG_TEXT.securityHeartbeat, 'info');
            }, INTERVALS_MS.securityHeartbeat);

            logSecurityEvent(LOG_TEXT.allMeasuresInitialized, 'success');
            
        } catch(error) {
            logSecurityEvent(LOG_TEXT.initializationFailed, 'critical', error.message);
        }
    }

    const WebsiteShield = Object.freeze({
        init: (runtimeConfig = {}) => {
            applyRuntimeConfig(runtimeConfig);
            return startSecurity();
        },
        updateConfig: (runtimeConfig = {}) => {
            applyRuntimeConfig(runtimeConfig);
            return getPublicSecurityState();
        },
        destroy: () => {
            stopSecurity();
            return getPublicSecurityState();
        },
        getState: () => getPublicSecurityState(),
        getConfig: () => ({ ...CONFIG })
    });

    window.WebsiteShield = WebsiteShield;

    // Cung cấp API tương thích ngược
    window.SecurityAPI = Object.freeze({
        getViolationCount: () => securityState.violations,
        isLocked: () => securityState.isLocked,
        getDeviceFingerprint: () => {
            if (!CONFIG.exposeFingerprintInApi || !securityState.deviceFingerprint) {
                return null;
            }
            return securityState.deviceFingerprint.slice(-8);
        },
        reportLegitimateUse: (reason) => logSecurityEvent(LOG_TEXT.legitimateUseReported, 'info', reason),
        init: WebsiteShield.init,
        updateConfig: WebsiteShield.updateConfig,
        destroy: WebsiteShield.destroy,
        getState: WebsiteShield.getState
    });

    // Bắt đầu bảo mật khi DOM đã sẵn sàng (nếu bật autoStart)
    function bootIfAutoStart() {
        if (!CONFIG.autoStart) {
            return;
        }

        const runtimeConfig = window.WebsiteShieldConfig && typeof window.WebsiteShieldConfig === 'object'
            ? window.WebsiteShieldConfig
            : {};
        WebsiteShield.init(runtimeConfig);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bootIfAutoStart);
    } else {
        bootIfAutoStart();
    }

})();