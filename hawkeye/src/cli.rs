use clap::Parser;

#[derive(Debug, Parser)]
#[command(arg_required_else_help(true))]
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

    /// Attach target, for uprobe
    #[arg(short, long)]
    pub(crate) attach_target: Option<String>,

    /// WxWork bot webhook
    #[arg(
        short,
        long,
        default_value = include_str!("../../.webhook")
    )]
    pub(crate) webhook: Option<String>,

    /// Hostname
    #[arg(long, default_value_t = hostname::get().unwrap().into_string().unwrap())]
    pub(crate) hostname: String,
}
