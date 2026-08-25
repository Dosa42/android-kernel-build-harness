mod app;
mod codex;
mod logging;
mod oauth;
mod schema;
mod storage;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1180.0, 760.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Codex Schema Engine",
        options,
        Box::new(|_| Ok(Box::<app::SchemaEngineApp>::default())),
    )
}
