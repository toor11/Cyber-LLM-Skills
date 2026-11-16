# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`android-app-security-component-and-deeplink`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Possible to steal any protected files on Android

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi. I have found an issue which allows to retrieve any files from '/data/data/com.owncloud.android/*' directory. The problem is in exported activity 'com.owncloud.android.ui.activity.ReceiveExternalFilesActivity' which accepts a URI to download files.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Cookie steal through content Uri

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary A misconfiguration in a content provider is allowing Brave for Android to download internal files to Downloads folder, making them accessible to other apps. A malicious app could order Brave to download the cookies database and retrieve it afterwards.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Vulnerabilities in exported activity WebView

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, i want to report the vulnerability found, Since the following activity 'com.pushio.manager.iam.ui.PushIOMessageViewActivity' has 'exported=true' it can be exploited by 3rd parties.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: [Zomato for Business Android] Vulnerability in exported activity WebView

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, i want to report the vulnerability found, Since the following activity 'com.application.zomatomerchant.home.HomeSalt' has 'exported="true"' it can be exploited by another application.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Private application files can be uploaded to Slack via malicious uploader

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi. I have found an issue which allows to retrieve any files from '/data/data/com.Slack/*' directory. The problem is in exported activity 'com.Slack.ui.UploadActivity' which accepts a URI to download files.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Possible to steal any protected files on Android

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi. I have found an issue which allows to retrieve any files from **_/data/data/com.harvestapp/*_** directory. The problem is in exported activity com.harvestapp.app.EditExpenseActivity which accepts URI to a pdf to be processed and saved it on SD Card which is world accessible...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: SQL Injection found in NextCloud Android App Content Provider

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Using Drozer, we identified com.nextcloud.client is vulnerable to Sql Injection here is output from drozer: dz> run scanner.provider.injection -a com.nextcloud.client Scanning com.nextcloud.client...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: [com.exness.android.pa Android] Universal XSS in webview. Lead to steal user cookies

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Details:** Package: com.exness.android.pa Name: Exness Version: 1.7.5-real-release **Description**: Third-app may use exported activity to load any url in internal webView.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
