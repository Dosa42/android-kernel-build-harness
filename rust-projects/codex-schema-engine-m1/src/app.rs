use crate::{codex, logging, oauth, scanner, schema, storage};
use eframe::egui;
use std::sync::mpsc::{self, Receiver, TryRecvError};

pub struct SchemaEngineApp {
    input: String,
    result: String,
    status: String,
    session: Option<oauth::OAuthSession>,
    busy: bool,
    rx: Option<Receiver<AppEvent>>,
    schema_job: egui::text::LayoutJob,
}

enum AppEvent {
    Login(Result<oauth::OAuthSession, String>),
    Answer(Result<String, String>, oauth::OAuthSession),
    Scan(Result<String, String>),
}

impl Default for SchemaEngineApp {
    fn default() -> Self {
        Self {
            input: String::new(),
            result: "Milestone 2 ready: run the mechanical system scan to discover Codex/schema files, or enter one Codex configuration question.".into(),
            status: format!("Embedded schema: {} lines · {} bytes", schema::line_count(), schema::byte_count()),
            session: storage::load_session(),
            busy: false,
            rx: None,
            schema_job: schema::syntax_job(),
        }
    }
}

impl SchemaEngineApp {
    fn start_login(&mut self) {
        if self.busy { return; }
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.busy = true;
        self.status = "Waiting for ChatGPT OAuth callback on localhost:1455…".into();
        std::thread::spawn(move || {
            let r = oauth::login().map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::Login(r));
        });
    }

    fn start_query(&mut self) {
        if self.busy || self.input.trim().is_empty() { return; }
        let Some(session) = self.session.clone() else {
            self.result = "AUTH_REQUIRED — Login with ChatGPT first.".into();
            return;
        };
        let user_input = self.input.trim().to_owned();
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.busy = true;
        self.status = "Schema Engine running…".into();
        std::thread::spawn(move || {
            let refreshed = oauth::refresh(&session).map_err(|e| e.to_string());
            match refreshed {
                Ok(s) => {
                    let answer = codex::ask(&s, &user_input).map_err(|e| e.to_string());
                    let _ = tx.send(AppEvent::Answer(answer, s));
                }
                Err(e) => { let _ = tx.send(AppEvent::Answer(Err(e), session)); }
            }
        });
    }

    fn start_scan(&mut self) {
        if self.busy { return; }
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.busy = true;
        self.result = "Mechanical scan running. This may inspect a very large number of files; latency is intentionally not optimized away.".into();
        self.status = "Milestone 2 mechanical system scan running…".into();
        std::thread::spawn(move || {
            let report = scanner::scan_system_json();
            let _ = tx.send(AppEvent::Scan(report));
        });
    }

    fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        match rx.try_recv() {
            Ok(AppEvent::Login(Ok(session))) => {
                logging::event("oauth", "login_success");
                let _ = storage::save_session(&session);
                self.session = Some(session);
                self.status = "ChatGPT OAuth connected.".into();
                self.busy = false;
                self.rx = None;
            }
            Ok(AppEvent::Login(Err(e))) => {
                logging::event("oauth_error", &e);
                self.result = format!("OAuth failed\n{e}");
                self.status = "OAuth failed.".into();
                self.busy = false;
                self.rx = None;
            }
            Ok(AppEvent::Answer(Ok(answer), session)) => {
                logging::event("codex", "response_completed");
                let _ = storage::save_session(&session);
                self.session = Some(session);
                self.result = answer;
                self.status = "Completed.".into();
                self.busy = false;
                self.rx = None;
            }
            Ok(AppEvent::Answer(Err(e), session)) => {
                logging::event("codex_error", &e);
                self.session = Some(session);
                self.result = format!("ENGINE_FAILED\n{e}");
                self.status = "Engine request failed.".into();
                self.busy = false;
                self.rx = None;
            }
            Ok(AppEvent::Scan(Ok(report))) => {
                logging::event("scanner", "mechanical_scan_completed");
                self.result = report;
                self.status = "Milestone 2 mechanical scan completed.".into();
                self.busy = false;
                self.rx = None;
            }
            Ok(AppEvent::Scan(Err(e))) => {
                logging::event("scanner_error", &e);
                self.result = format!("SCAN_FAILED\n{e}");
                self.status = "Milestone 2 mechanical scan failed.".into();
                self.busy = false;
                self.rx = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.result = "ENGINE_FAILED\nBackground worker disconnected.".into();
                self.busy = false;
                self.rx = None;
            }
        }
    }
}

impl eframe::App for SchemaEngineApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.busy { ctx.request_repaint_after(std::time::Duration::from_millis(100)); }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("Codex Schema Engine");
                ui.separator();
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.session.is_some() {
                        if ui.button("Sign out").clicked() && !self.busy {
                            let _ = storage::clear_session();
                            self.session = None;
                            self.status = "Signed out.".into();
                        }
                        ui.label("ChatGPT: connected");
                    } else if ui.add_enabled(!self.busy, egui::Button::new("Login with ChatGPT")).clicked() {
                        self.start_login();
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |cols| {
                cols[0].heading("Embedded config-schema.json");
                cols[0].label("Full schema is compiled into the application and sent as the Codex instructions field.");
                cols[0].separator();
                egui::ScrollArea::vertical().id_salt("schema").show(&mut cols[0], |ui| {
                    ui.add(egui::Label::new(self.schema_job.clone()).selectable(true));
                });

                cols[1].heading("Milestone 2 — Mechanical discovery");
                cols[1].label("Deterministic filesystem discovery only. No AI classification, no edit/write tools, no silent permission skipping.");
                if cols[1].add_enabled(!self.busy, egui::Button::new("Scan system for Codex/schema files")).clicked() {
                    self.start_scan();
                }
                cols[1].separator();
                cols[1].heading("Result");
                egui::ScrollArea::vertical().max_height(330.0).show(&mut cols[1], |ui| {
                    ui.add(egui::Label::new(egui::RichText::new(&self.result).monospace()).selectable(true));
                });
                cols[1].separator();
                cols[1].label("Optional M1 schema question:");
                cols[1].add(egui::TextEdit::multiline(&mut self.input).desired_rows(5).hint_text("Example: My PreToolUse hook never runs. What in the schema could explain this?"));
                if cols[1].add_enabled(!self.busy && self.session.is_some() && !self.input.trim().is_empty(), egui::Button::new("Run Schema Engine")).clicked() {
                    self.start_query();
                }
                cols[1].separator();
                cols[1].monospace(format!("model: {}", codex::MODEL));
                cols[1].monospace("M2 scanner: mechanical / deterministic");
                cols[1].monospace("M2 scanner tools: read-only filesystem inspection");
                cols[1].monospace("store: false");
            });
        });
    }
}
