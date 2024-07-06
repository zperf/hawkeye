use clap::Parser;

#[derive(Debug, Parser)]
pub(crate) struct Opt {
    /// Process to be traced
    #[arg(short, long)]
    pub(crate) pid: Option<i32>,

    /// User space function names
    #[arg(short, long)]
    pub(crate) ufns: Option<Vec<String>>,

    /// Kernel space function names
    #[arg(short, long)]
    pub(crate) kfns: Option<Vec<String>>,

    /// Attach target
    #[arg(short, long)]
    pub(crate) attach_target: String,

    /// WxWork bot webhook
    #[arg(
        short,
        long,
        default_value = include_str!("../../.webhook")
    )]
    pub(crate) webhook: Option<String>,

    /// Hostname
    #[arg(long)]
    pub(crate) hostname: String,
}
