use colored::*;
use prettytable::{Table, row};
use regex::Regex;
use reqwest::{Client, header::HeaderMap};
use scraper::{Html, Selector};
use std::time::Duration;
use std::{thread, io};
use tokio::net::lookup_host;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;
use textwrap::wrap;
use terminal_size::{Width, terminal_size};
use serde::Deserialize;
use std::collections::HashMap;

fn get_terminal_width(default: usize) -> usize {
    if let Some((Width(w), _)) = terminal_size() {
        w as usize
    } else {
        default
    }
}

fn banner(term_width: usize) {
    let banner = r#"
 ██████╗██╗   ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║     ██║   ██║█████╗  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║     ╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╗ ╚████╔╝ ███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                    
                https://github.com/zt3x2b
"#;
    for line in banner.lines() {
        let centered = format!("{:^1$}", line, term_width);
        println!("{}", centered);
        thread::sleep(Duration::from_millis(8));
    }
}

async fn resolve_to_ip(host: &str) -> Result<String, String> {
    let host = if host.starts_with("http://") || host.starts_with("https://") {
        match Url::parse(host) {
            Ok(u) => u.host_str().ok_or("No host in URL".to_string())?.to_string(),
            Err(e) => return Err(format!("Invalid URL: {}", e)),
        }
    } else {
        host.to_string()
    };

    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Ok(host);
    }

    let addr = format!("{}:0", host);
    match lookup_host(addr).await {
        Ok(mut addrs) => {
            if let Some(sock) = addrs.next() {
                Ok(sock.ip().to_string())
            } else {
                Err("No addresses found".to_string())
            }
        }
        Err(e) => Err(format!("DNS resolution error: {}", e)),
    }
}

async fn reverse_dns(ip: &str) -> Vec<String> {
    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let parsed = match ip.parse::<std::net::IpAddr>() {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    match resolver.reverse_lookup(parsed).await {
        Ok(resp) => resp.iter().map(|r| r.to_utf8()).collect(),
        Err(_) => vec![],
    }
}

async fn fetch_shodan(ip: &str, client: &Client) -> Result<(String, HeaderMap), String> {
    let url = format!("https://shodan.io/host/{}", ip);
    let res = client.get(&url)
        .header("User-Agent", "CVERecon-Rust/1.0")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Shodan returned status: {}", res.status()));
    }
    let headers = res.headers().clone();
    let body = res.text().await.map_err(|e| e.to_string())?;
    Ok((body, headers))
}

fn extract_cves_from_html(html: &str) -> Vec<String> {
    let re = Regex::new(r"\bCVE-\d{4}-\d{4,}\b").unwrap();
    let mut set = std::collections::BTreeSet::new();
    for caps in re.captures_iter(html) {
        if let Some(m) = caps.get(0) { set.insert(m.as_str().to_string()); }
    }
    let mut v: Vec<_> = set.into_iter().collect();
    v.sort_by(|a,b| b.cmp(a));
    v
}

fn extract_ports_from_html(html: &str) -> Vec<String> {
    let fragment = Html::parse_document(html);
    let mut ports = Vec::new();
    if let Ok(sel) = Selector::parse("div#ports a.bg-primary") {
        for el in fragment.select(&sel) {
            let txt = el.text().collect::<Vec<_>>().join("").trim().to_string();
            if !txt.is_empty() {
                ports.push(txt);
            }
        }
    }
    if ports.is_empty() {
        let re = Regex::new(r"\b([0-9]{1,5})\b").unwrap();
        for cap in re.captures_iter(html) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str().to_string();
                if let Ok(pn) = s.parse::<u16>() {
                    if pn > 0 && pn <= 65535 {
                        ports.push(s);
                    }
                }
            }
        }
        ports.sort();
        ports.dedup();
    }
    ports
}

#[derive(Debug, Deserialize)]
struct WApp {
    html: Option<String>,
    headers: Option<HashMap<String, String>>,
    cookies: Option<String>,
    scripts: Option<Vec<String>>,
}

type AppsDB = HashMap<String, WApp>;

fn extract_technologies(html: &str, headers: &HeaderMap, db: &AppsDB) -> Vec<String> {
    let mut techs = Vec::new();
    let doc = Html::parse_document(html);

    let selectors = vec![".service-name", ".badge", ".tag", "span[class*=tech]"];

    for sel_str in selectors {
        if let Ok(sel) = Selector::parse(sel_str) {
            for el in doc.select(&sel) {
                let t = el.text().collect::<Vec<_>>().join("").trim().to_string();
                if !t.is_empty() { techs.push(t); }
            }
        }
    }

    if techs.is_empty() {
        let reg = Regex::new(r"(Apache|nginx|IIS|PHP|OpenSSH|MySQL|PostgreSQL|Redis|Docker|NodeJS|ASP\.NET)").unwrap();
        for cap in reg.captures_iter(html) {
            techs.push(cap.get(0).unwrap().as_str().to_string());
        }
        for (k, v) in headers.iter() {
            let hv = format!("{}: {}", k.as_str(), v.to_str().unwrap_or(""));
            for (name, _) in db.iter() {
                if hv.contains(name) {
                    techs.push(name.clone());
                }
            }
        }
    }

    techs.sort();
    techs.dedup();
    techs
}

#[tokio::main]
async fn main() {
    let term_width = get_terminal_width(120);

    if cfg!(target_os = "windows") {
        let _ = std::process::Command::new("cmd").arg("/C").arg("cls").status();
    } else {
        let _ = std::process::Command::new("clear").status();
    }

    banner(term_width);

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap();

    let wapp_db: AppsDB = match std::fs::read_to_string("apps.json") {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => HashMap::new(),
    };

    loop {
        println!("\nEnter a target (IP or URL) :");
        let mut target = String::new();
        if io::stdin().read_line(&mut target).is_err() {
            eprintln!("Read Error of stdin. Exit.");
            break;
        }
        let target = target.trim();
        if target.eq_ignore_ascii_case("exit") {
            println!("{}", "Bye.".green());
            break;
        }
        if target.is_empty() {
            continue;
        }

        match resolve_to_ip(target).await {
            Ok(ip) => {
                println!("{} {}", "IP Address:".bold(), ip.cyan());

                let hosts = reverse_dns(&ip).await;
                let host_display = if hosts.is_empty() { "None found".to_string() } else { hosts.join(", ") };

                let (shodan_html, headers) = match fetch_shodan(&ip, &client).await {
                    Ok((html, h)) => (html, h),
                    Err(e) => {
                        eprintln!("Error fetching Shodan page: {}", e);
                        (String::new(), HeaderMap::new())
                    }
                };

                let ports = extract_ports_from_html(&shodan_html);
                let ports_display = if ports.is_empty() { "No open ports found".to_string() } else { ports.join(", ") };

                let cves = extract_cves_from_html(&shodan_html);
                let cve_display = if cves.is_empty() { "No CVEs found".to_string() } else { cves.join(", ") };

                let technologies = extract_technologies(&shodan_html, &headers, &wapp_db);
                let tech_display = if technologies.is_empty() { 
                    "No technologies found".to_string() 
                } else { 
                    technologies.join(", ") 
                };

                let mut table = Table::new();
                table.add_row(row![bFg => "Category", "Details"]);

                let category_col_width = 12usize;
                let details_width = if term_width > category_col_width + 4 {
                    term_width - category_col_width - 4
                } else {
                    60usize
                };

                let rows: Vec<(&str, String)> = vec![
                    ("IP Address", ip.clone()),
                    ("Hostnames", host_display.clone()),
                    ("Open Ports", ports_display.clone()),
                    ("Technologies", tech_display.clone()),
                    ("CVEs", cve_display.clone()),
                ];

                for (cat, details) in rows {
                    let details = if details.is_empty() { "-".to_string() } else { details };
                    let wrapped_lines = wrap(&details, details_width);
                    let details_wrapped = wrapped_lines.join("\n");
                    table.add_row(row![cat, details_wrapped]);
                }

                table.printstd();

                println!("\nPress Enter to continue...");
                let mut _s = String::new();
                let _ = io::stdin().read_line(&mut _s);
            }
            Err(e) => {
                eprintln!("Resolution Failed : {}", e);
            }
        }
    }
}
