use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use std::time::Duration;

pub type TokioResolver = Resolver<TokioConnectionProvider>;

pub struct CachingDnsResolver {
    resolver: TokioResolver,
}

impl CachingDnsResolver {
    pub fn new(_dns_servers: &[IpAddr]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 1024;
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;

        let resolver = Resolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();

        Ok(Self { resolver })
    }

    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        match self.resolver.lookup_ip(hostname).await {
            Ok(response) => {
                let addrs: Vec<IpAddr> = response.iter().collect();
                if addrs.is_empty() {
                    Err(format!("No addresses found for {}", hostname))
                } else {
                    log::debug!("DNS resolved {} -> {:?}", hostname, addrs);
                    Ok(addrs)
                }
            }
            Err(e) => Err(format!("DNS resolution failed: {}", e)),
        }
    }
}
