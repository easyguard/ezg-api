use tide::http::headers::HeaderValue;
use tide::security::CorsMiddleware;
use tide::security::Origin;
use tide::Error;
use tide::Request;
use tide::prelude::*;
use std::fs;
use std::path::Path;

const EZG_ROOT: &str = "/etc/easyguard";

#[derive(Debug, Deserialize)]
struct FirewallRule {
	port: u16,
	protocol: String
}

#[derive(Debug, Deserialize)]
struct FirewallPath {
	zone: String,
	chain: String,
	rule: FirewallRule
}

#[derive(Debug, Deserialize)]
struct DNSPatch {
	option: String,
	value: String
}

#[async_std::main]
async fn main() -> tide::Result<()> {
	let mut app = tide::new();
	app.at("/api/firewall").get(get_firewall);
	app.at("/api/firewall/rule").put(put_firewall_rule);
	app.at("/api/firewall/rule").delete(delete_firewall_rule);
	app.at("/api/dns").get(get_dns);
	app.at("/api/dns").patch(patch_dns);
	app.at("/api/*").all(err404);

	let cors = CorsMiddleware::new()
    .allow_methods("GET, PUT, DELETE, POST, PATCH, OPTIONS".parse::<HeaderValue>().unwrap())
    .allow_origin(Origin::from("*"))
    .allow_credentials(false);
	app.with(cors);

	app.listen("0.0.0.0:8080").await?;
	Ok(())
}

async fn err404(mut req: Request<()>) -> tide::Result {
	Err(Error::from_str(404, "Not Found"))
}

async fn get_firewall(mut req: Request<()>) -> tide::Result {
	let firewall_text = fs::read_to_string(Path::new(EZG_ROOT).join("firewall.json")).expect("Unable to read file");
	println!("{}", firewall_text);
	Ok(firewall_text.into())
}

async fn put_firewall_rule(mut req: Request<()>) -> tide::Result {
	let FirewallPath { zone, chain, rule } = req.body_json().await?; // { "zone": "zoneName", "chain": "chainName", "rule": {<object to add>} }

	// run bash script to add rule
	let output = std::process::Command::new("bash")
		.current_dir(EZG_ROOT)
		.arg(Path::new(EZG_ROOT).join("ezg").to_str().unwrap())
		.arg("firewall")
		.arg("rule")
		.arg(zone)
		.arg(chain)
		.arg("add")
		.arg(rule.protocol)
		.arg(rule.port.to_string())
		.output()
		.expect("failed to execute process");

	Ok("{\"success\": true}".into())
}

async fn delete_firewall_rule(mut req: Request<()>) -> tide::Result {
	let FirewallPath { zone, chain, rule } = req.body_json().await?; // { "zone": "zoneName", "chain": "chainName", "rule": {<object to add>} }

	// run bash script to add rule
	let output = std::process::Command::new("bash")
		.current_dir(EZG_ROOT)
		.arg(Path::new(EZG_ROOT).join("ezg").to_str().unwrap())
		.arg("firewall")
		.arg("rule")
		.arg(zone)
		.arg(chain)
		.arg("remove")
		.arg(rule.protocol)
		.arg(rule.port.to_string())
		.output()
		.expect("failed to execute process");

	Ok("{\"success\": true}".into())
}

async fn get_dns(mut req: Request<()>) -> tide::Result {
	let dns_text = fs::read_to_string(Path::new(EZG_ROOT).join("dns.json")).expect("Unable to read file");
	println!("{}", dns_text);
	Ok(dns_text.into())
}

async fn patch_dns(mut req: Request<()>) -> tide::Result {
	let DNSPatch { option, value } = req.body_json().await?;

	// run bash script to add rule
	let output = std::process::Command::new("bash")
		.current_dir(EZG_ROOT)
		.arg(Path::new(EZG_ROOT).join("ezg").to_str().unwrap())
		.arg("dns")
		.arg("set")
		.arg(option)
		.arg(value)
		.output()
		.expect("failed to execute process");

	Ok("{\"success\": true}".into())
}

// async fn order_shoes(mut req: Request<()>) -> tide::Result {
// 	let Animal { name, legs } = req.body_json().await?;
// 	Ok(format!("Hello, {}! I've put in an order for {} shoes", name, legs).into())
// }