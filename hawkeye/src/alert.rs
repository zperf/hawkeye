use serde_json::json;
use hawkeye_common::Event;

pub(crate) async fn send(webhook: &String, message: String) -> Result<(), anyhow::Error> {
    let body = json!({
        "msgtype": "text",
        "text": {
            "content": message
        }
    });

    let client = reqwest::Client::new();
    client.post(webhook).json(&body).send().await?;
    Ok(())
}

#[cfg(not(feature = "alert-cn"))]
pub(crate) fn get_alert_message(fn_name: &String, machine: &String, event: &Event) -> String {
    format!(
        "[ALERT] {} takes too loooooooong! hostname: {}, pid: {}, elapsed: {}ns",
        fn_name, machine, event.pid, event.elapsed_ns
    )
}

#[cfg(feature = "alert-cn")]
pub(crate) fn get_message(fn_name: &String, hostname: &String, event: &Event) -> String {
    format!(
        "[警告] {} 上的 {} 实在是太慢了！居然消耗了 {} 纳秒！快去看看服务 {} 吧！",
        hostname, fn_name, event.elapsed_ns, event.pid
    )
}
