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
struct Animal {
	name: String,
	legs: u16,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
	let mut app = tide::new();
	app.at("/api/firewall").get(get_firewall);
	// app.at("/api/firewall/rule").put(put_firewall_rule);
	app.at("/api/*").all(err404);

	let cors = CorsMiddleware::new()
    .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
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
	let rule = req.body_string().await?; // { "zone": "zoneName", "chain": "chainName", "rule": {<object to add>} }
	let rule_json: serde_json::Value = serde_json::from_str(&rule).expect("Invalid JSON 1");
	let zone = rule_json["zone"].as_str().expect("Invalid JSON 2");
	let chain = rule_json["chain"].as_str().expect("Invalid JSON 3");
	let rule = rule_json["rule"].as_object().expect("Invalid JSON 4");

	let mut firewall: serde_json::Value = serde_json::from_str(&fs::read_to_string(Path::new(EZG_ROOT).join("firewall.json")).expect("Unable to read file")).expect("Invalid JSON 5");
	// Find the zone and chain
	// { "zones": [ { "name": "...", "<chains>": { "ports": [{...}, <add here>] } }, ... ] }
	let zones = firewall["zones"].as_array_mut().expect("Invalid JSON 6");
	let zone_index = zones.iter().position(|z| z["name"].as_str().expect("Invalid JSON") == zone).expect("Zone not found 7");
	let chains = zones[zone_index][chain].as_array_mut().expect("Invalid JSON 8");
	chains.push(serde_json::Value::Object(rule.clone()));

	fs::write(Path::new(EZG_ROOT).join("firewall2.json"), serde_json::to_string_pretty(&firewall).expect("Invalid JSON 9")).expect("Unable to write file");

	Ok("{\"success\": \"true\"}".into())
}

async fn order_shoes(mut req: Request<()>) -> tide::Result {
	let Animal { name, legs } = req.body_json().await?;
	Ok(format!("Hello, {}! I've put in an order for {} shoes", name, legs).into())
}