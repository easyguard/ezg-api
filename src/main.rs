use async_std::io::prelude::BufReadExt as _;
use async_std::process::Command;
use async_std::stream::StreamExt as _;
use tide::http::headers::HeaderValue;
use tide::security::CorsMiddleware;
use tide::security::Origin;
use tide::sse;
use tide::Error;
use tide::Next;
use tide::Request;
use tide::prelude::*;
use tide::Response;
use tide::StatusCode;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

// const EZG_ROOT: &str = "/etc/easyguard";
const CONFIG_ROOT: &str = "/etc/config";

#[derive(Debug, Deserialize)]
struct FirewallRule {
	port: u16,
	protocol: String,
	r#type: String
}

#[derive(Debug, Deserialize)]
struct FirewallPath {
	zone: String,
	chain: String,
	rule: FirewallRule
}

#[derive(Debug, Deserialize)]
struct IncludesPatch {
	zone: String,
	chain: String,
	includes: Vec<String>
}

// Authenticate users against /etc/shadow
fn authenticate_user(username: &str, password: &str) -> bool {
	let hash = shadow::Shadow::from_name(username);
	if hash.is_none() {
		return false;
	}
	let hash = hash.unwrap();
	let correct = pwhash::unix::verify(password, &hash.password);
	return correct;
}

fn auth_middleware<'a>(
	request: Request<()>,
	next: Next<'a, ()>,
) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'a>> {
	// Authorization: Basic <base64(username:password)>
	let auth_header = request.header("Authorization");
	if auth_header.is_none() {
		let res = Response::new(StatusCode::Unauthorized);
		return Box::pin(async { Ok(res) });
	}
	let auth_header = auth_header.unwrap();
	let auth_header = auth_header.get(0).unwrap();
	let auth_header = auth_header.as_str();
	let auth_header = auth_header.split_whitespace().collect::<Vec<&str>>();
	if auth_header.len() != 2 {
		let res = Response::new(StatusCode::Unauthorized);
		return Box::pin(async { Ok(res.into()) });
	}
	let auth_header = auth_header[1];
	let auth_header = base64::decode(auth_header).unwrap();
	let auth_header = String::from_utf8(auth_header).unwrap();
	let auth_header = auth_header.split(":").collect::<Vec<&str>>();
	if auth_header.len() != 2 {
		let res = Response::new(StatusCode::Unauthorized);
		return Box::pin(async { Ok(res.into()) });
	}
	let username = auth_header[0];
	let password = auth_header[1];
	if !authenticate_user(username, password) {
		let res = Response::new(StatusCode::Unauthorized);
		return Box::pin(async { Ok(res.into()) });
	}
	Box::pin(async move {
		Ok(next.run(request).await)
	})
}

#[async_std::main]
async fn main() -> tide::Result<()> {
	let mut app = tide::new();

	let cors = CorsMiddleware::new()
    .allow_methods("GET, PUT, DELETE, POST, PATCH, OPTIONS".parse::<HeaderValue>().unwrap())
    .allow_origin(Origin::from("*"))
    .allow_credentials(false);
	app.with(cors);

	// Require authentication for all routes
	app.with(auth_middleware);
	app.at("/api/ping").get(|_| async { Ok("pong") });
	app.at("/api/commit").post(commit);
	app.at("/api/firewall").get(get_firewall);
	app.at("/api/firewall/rule").put(put_firewall_rule);
	app.at("/api/firewall/rule").delete(delete_firewall_rule);
	app.at("/api/firewall/templates").get(get_templates);
	app.at("/api/firewall/template/:template").get(get_template);
	app.at("/api/firewall/template/:template").patch(patch_template);
	app.at("/api/firewall/includes").patch(patch_includes);
	app.at("/api/dns").get(get_dns);
	app.at("/api/dns").patch(patch_dns);
	app.at("/api/network").get(get_network);
	app.at("/api/network").patch(patch_network);
	app.at("/api/ip").get(get_ip);
	app.at("/api/link").get(get_link);
	app.at("/api/route").get(get_route);
	app.at("/api/ping/:host").get(get_ping);
	app.at("/api/traceroute/:host").get(get_traceroute);
	app.at("/api/devices/:interface").get(sse::endpoint(|req, sender| async move {
    let interface = req.param("interface").unwrap();

    let mut child = Command::new("arp-scan")
			.arg("-i")
			.arg(interface)
			.arg("-o")
			.arg("json")
			.stdout(std::process::Stdio::piped())
			.spawn()
			.expect("Failed to start arp-scan");

    if let Some(stdout) = child.stdout.take() {
			let reader = async_std::io::BufReader::new(stdout);
			let mut lines = reader.lines();

			while let Some(line) = lines.next().await {
				let line = line.expect("Failed to read line");
				sender.send("message", &line, None).await?;
			}
    }

    Ok(())
	}));
	app.at("/api/apk").post(apk);
	app.at("/api/world").get(get_world);
	// app.at("/api/leases").get(get_leases);
	// app.at("/api/mac").post(get_mac);
	app.at("/api/*").all(err404);

	app.listen("0.0.0.0:48247").await?;
	Ok(())
}

async fn err404(mut _req: Request<()>) -> tide::Result {
	Err(Error::from_str(404, "Not Found"))
}

async fn commit(mut _req: Request<()>) -> tide::Result {
	std::process::Command::new("lbu")
		.arg("ci")
		.arg("-d")
		.output()
		.expect("failed to execute process");
	Ok("{\"success\": true}".into())
}

async fn get_firewall(mut _req: Request<()>) -> tide::Result {
	let firewall_text = fs::read_to_string(Path::new(CONFIG_ROOT).join("firewall.json")).expect("Unable to read file");
	println!("{}", firewall_text);
	Ok(firewall_text.into())
}

// async fn get_leases(mut req: Request<()>) -> tide::Result {
// 	let leases_text = fs::read_to_string(Path::new(EZG_ROOT).join("dhcp_leases.json")).expect("Unable to read file");
// 	println!("{}", leases_text);
// 	Ok(leases_text.into())
// }

// async fn get_mac(mut req: Request<()>) -> tide::Result {
// 	let mac = req.body_string().await?;

// 	let output = std::process::Command::new("bash")
// 		.current_dir(EZG_ROOT)
// 		.arg(Path::new(EZG_ROOT).join("maclookup.sh").to_str().unwrap())
// 		.arg(mac)
// 		.output()
// 		.expect("failed to execute process");

// 	Ok(String::from_utf8(output.stdout).unwrap().into())
// }

async fn put_firewall_rule(mut req: Request<()>) -> tide::Result {
	let FirewallPath { zone, chain, rule } = req.body_json().await?; // { "zone": "zoneName", "chain": "chainName", "rule": {<object to add>} }

	let port = if rule.protocol == "icmp" {
		rule.r#type
	} else {
		rule.port.to_string()
	};

	// run bash script to add rule
	std::process::Command::new("limes")
		// .current_dir(EZG_ROOT)
		// .arg(Path::new(EZG_ROOT).join("ezg").to_str().unwrap())
		// .arg("firewall")
		.arg("rule")
		.arg(zone)
		.arg(chain)
		.arg("add")
		.arg(rule.protocol)
		.arg(port)
		.output()
		.expect("failed to execute process");

	Ok("{\"success\": true}".into())
}

async fn delete_firewall_rule(mut req: Request<()>) -> tide::Result {
	let FirewallPath { zone, chain, rule } = req.body_json().await?; // { "zone": "zoneName", "chain": "chainName", "rule": {<object to add>} }

	let port = if rule.protocol == "icmp" {
		rule.r#type
	} else {
		rule.port.to_string()
	};

	// run bash script to add rule
	std::process::Command::new("limes")
		// .current_dir(EZG_ROOT)
		// .arg(Path::new(EZG_ROOT).join("ezg").to_str().unwrap())
		// .arg("firewall")
		.arg("rule")
		.arg(zone)
		.arg(chain)
		.arg("remove")
		.arg(rule.protocol)
		.arg(port)
		.output()
		.expect("failed to execute process");

	Ok("{\"success\": true}".into())
}

async fn get_templates(mut _req: Request<()>) -> tide::Result {
	let templates = fs::read_dir(Path::new(CONFIG_ROOT).join("firewall").join("templates"));
	let mut templates = match templates {
		Ok(templates) => templates,
		Err(_) => return Ok("[]".into())
	};
	let mut template_list = Vec::new();
	while let Some(template) = templates.next() {
		let template = template.unwrap();
		let template = template.file_name();
		let template = template.into_string();
		let template = template.unwrap();
		template_list.push(template);
	}
	Ok(serde_json::to_string(&template_list).unwrap().into())
}

async fn get_template(req: Request<()>) -> tide::Result {
	let template_name = req.param("template").unwrap();
	let template_text = fs::read_to_string(Path::new(CONFIG_ROOT).join("firewall").join("templates").join(format!("{template_name}.json"))).expect("Unable to read file");
	Ok(template_text.into())
}

async fn patch_template(mut req: Request<()>) -> tide::Result {
	let template_text = req.body_string().await?;
	let template_name = req.param("template").unwrap();
	fs::write(Path::new(CONFIG_ROOT).join("firewall").join("templates").join(format!("{template_name}.json")), template_text).expect("Unable to write file");
	Ok("{\"success\": true}".into())
}

async fn patch_includes(mut req: Request<()>) -> tide::Result {
	let IncludesPatch { zone, chain, includes } = req.body_json().await?;
	let includes = serde_json::to_string(&includes).unwrap();

	// run bash script to add rule
	std::process::Command::new("limes")
		// .current_dir(EZG_ROOT)
		// .arg(Path::new(EZG_ROOT).join("ezg").to_str().unwrap())
		// .arg("firewall")
		.arg("includes")
		.arg(zone)
		.arg(chain)
		.arg("replace")
		.arg(includes)
		.output()
		.expect("failed to execute process");

	Ok("{\"success\": true}".into())
}

async fn get_dns(mut _req: Request<()>) -> tide::Result {
	let dns_text = fs::read_to_string("/etc/blocky/config.yml").expect("Unable to read file");
	println!("{}", dns_text);
	Ok(dns_text.into())
}

async fn patch_dns(mut req: Request<()>) -> tide::Result {
	// rename config.yml to config.yml.bak
	fs::rename("/etc/blocky/config.yml", "/etc/blocky/config.yml.bak").expect("Unable to rename file");
	// write config.yml from request body
	let dns_text = req.body_string().await?;
	fs::write("/etc/blocky/config.yml", dns_text).expect("Unable to write file");
	// restart blocky
	std::process::Command::new("rc-service")
		.arg("blocky")
		.arg("restart")
		.output()
		.expect("failed to execute process");
	Ok("{\"success\": true}".into())
}

async fn get_network(mut _req: Request<()>) -> tide::Result {
	let network_text = fs::read_to_string(Path::new(CONFIG_ROOT).join("network.toml")).expect("Unable to read file");
	println!("{}", network_text);
	Ok(network_text.into())
}

async fn patch_network(mut req: Request<()>) -> tide::Result {
	fs::rename(Path::new(CONFIG_ROOT).join("network.toml"), Path::new(CONFIG_ROOT).join("network.toml.bak")).expect("Unable to rename file");
	let network_text = req.body_string().await?;
	fs::write(Path::new(CONFIG_ROOT).join("network.toml"), network_text).expect("Unable to write file");
	Ok("{\"success\": true}".into())
}

async fn get_ip(mut _req: Request<()>) -> tide::Result {
	let output = std::process::Command::new("ip")
		.arg("a")
		.output()
		.expect("failed to execute process");
	Ok(String::from_utf8(output.stdout).unwrap().into())
}

async fn get_link(mut _req: Request<()>) -> tide::Result {
	let output = std::process::Command::new("ip")
		.arg("link")
		.output()
		.expect("failed to execute process");
	Ok(String::from_utf8(output.stdout).unwrap().into())
}

async fn get_route(mut _req: Request<()>) -> tide::Result {
	let output = std::process::Command::new("ip")
		.arg("route")
		.output()
		.expect("failed to execute process");
	Ok(String::from_utf8(output.stdout).unwrap().into())
}

async fn get_ping(req: Request<()>) -> tide::Result {
	let host = req.param("host").unwrap();
	let output = std::process::Command::new("ping")
		.arg("-c")
		.arg("1")
		.arg(host)
		.output()
		.expect("failed to execute process");
	Ok(String::from_utf8(output.stdout).unwrap().into())
}

async fn get_traceroute(req: Request<()>) -> tide::Result {
	let host = req.param("host").unwrap();
	let output = std::process::Command::new("traceroute")
		.arg(host)
		.output()
		.expect("failed to execute process");
	Ok(String::from_utf8(output.stdout).unwrap().into())
}

async fn apk(mut req: Request<()>) -> tide::Result {
	// req body: add blah  or   del blah    or something else
	let apk_text = req.body_string().await?;
	let apk_text = apk_text.split_whitespace().collect::<Vec<&str>>();
	let mut command = std::process::Command::new("apk");
	for arg in apk_text {
		command.arg(arg);
	}
	let output = command.output().expect("failed to execute process");
	Ok(String::from_utf8(output.stdout).unwrap().into())
}

async fn get_world(_req: Request<()>) -> tide::Result {
	let world_text = fs::read_to_string("/etc/apk/world").expect("Unable to read file");
	println!("{}", world_text);
	Ok(world_text.into())
}
