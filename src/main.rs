use network_scan_map::app::NetworkApp;

fn main() -> eframe::Result {
    let args: Vec<_> = std::env::args().collect();
    if args.iter().any(|s| s == "--network-info") {
        println!("{:#?}", network_scan_map::platform::network_info());
        return Ok(());
    }
    let smoke = args.iter().any(|s| s == "--smoke-test");
    let demo = args.iter().any(|s| s == "--demo");
    eframe::run_native(
        "NetworkScanMap",
        eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1280.0, 820.0]),
            ..Default::default()
        },
        Box::new(move |_cc| Ok(Box::new(NetworkApp::new(smoke, demo)))),
    )
}
