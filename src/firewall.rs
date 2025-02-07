use serde::Deserialize;

#[derive(Deserialize)]
pub struct FirewallConfig {
	pub zones: Vec<Zone>
}

#[derive(Deserialize)]
pub struct Zone {
	pub name: String,
	pub input: Option<Chain>,
	pub output: Option<Chain>,
	pub forward: Option<Vec<Forward>>
}

#[derive(Deserialize)]
pub struct Chain {
	pub include: Option<Vec<String>>
}

#[derive(Deserialize)]
pub struct Forward {
	pub dest: String,
	pub include: Option<Vec<String>>
}