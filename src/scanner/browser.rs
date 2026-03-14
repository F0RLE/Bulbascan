use std::path::{Path, PathBuf};
use std::time::Duration;

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::AddScriptToEvaluateOnNewDocumentParams;
use futures::StreamExt;
use tokio::task::JoinHandle;

use crate::service_profiles;

use super::types::{ScanResult, Verdict};

pub(crate) fn detect_browser_binary() -> Option<PathBuf> {
    let candidates: &[&str] = if cfg!(target_os = "windows") {
        &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    } else {
        // Linux and other Unix-like
        &[
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/snap/bin/chromium",
            "/usr/bin/microsoft-edge",
        ]
    };

    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

pub(crate) fn browser_proxy_server_arg(proxy: &str) -> Option<String> {
    let parsed = url::Url::parse(proxy).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    let host_with_port = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    match parsed.scheme() {
        "socks5" | "socks5h" => Some(format!("socks5://{host_with_port}")),
        "http" | "https" if parsed.username().is_empty() && parsed.password().is_none() => {
            Some(format!("http://{host_with_port}"))
        }
        _ => None,
    }
}

pub(crate) fn should_try_browser_verify(result: &ScanResult, domain: &str) -> bool {
    service_profiles::should_use_browser_verification(domain)
        && !matches!(result.verdict, Verdict::GeoBlocked | Verdict::Captcha)
        && matches!(
            result.verdict,
            Verdict::Accessible
                | Verdict::WafBlocked
                | Verdict::UnexpectedStatus
                | Verdict::Unreachable
        )
}

pub(crate) async fn run_browser_dom_dump(
    browser_path: &Path,
    url: &str,
    proxy: Option<&str>,
) -> anyhow::Result<String> {
    let profile = std::env::temp_dir().join(format!("bulba-browser-{}", fastrand::u64(..)));
    
    let mut config_builder = BrowserConfig::builder()
        .chrome_executable(browser_path)
        .user_data_dir(&profile)
        .window_size(1920, 1080)
        .no_sandbox()
        .disable_default_args();

    // Evasion arguments
    let mut args = vec![
        "--headless=new".to_string(),
        "--disable-gpu".to_string(),
        "--disable-blink-features=AutomationControlled".to_string(),
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36".to_string(),
        "--accept-lang=en-US,en;q=0.9".to_string(),
    ];

    if let Some(proxy_str) = proxy.and_then(browser_proxy_server_arg) {
        args.push(format!("--proxy-server={proxy_str}"));
    }

    config_builder = config_builder.args(args);

    let (mut browser, mut handler) = match Browser::launch(config_builder.build().map_err(|e| anyhow::anyhow!("config build error: {e}"))?).await {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&profile);
            return Err(anyhow::anyhow!("failed to launch browser: {e}"));
        }
    };

    let handler_task: JoinHandle<()> = tokio::task::spawn(async move {
        loop {
            let _ = handler.next().await;
        }
    });

    let page_result = async {
        let page = browser.new_page("about:blank").await?;
        
        // Evasion: CDP script injection to overwrite webdriver flag completely.
        let injection_script = r#"
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
            window.chrome = { runtime: {} };
        "#;
        
        page.execute(AddScriptToEvaluateOnNewDocumentParams::builder().source(injection_script).build().unwrap()).await?;

        // Navigate and wait for the page to settle
        page.goto(url).await?;
        page.wait_for_navigation().await?;
        
        // Give it a brief moment for Cloudflare/JS to execute
        tokio::time::sleep(Duration::from_secs(2)).await;

        let content = page.content().await?;
        Ok::<String, anyhow::Error>(content)
    }
    .await;

    // Cleanup
    browser.close().await.ok();
    handler_task.abort();
    let _ = std::fs::remove_dir_all(&profile);

    page_result
}

