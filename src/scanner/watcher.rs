use crate::config::RouteConfig;
use crate::scanner::detector::ScannerDetector;
use crate::scanner::model::ScannerModel;
use arc_swap::ArcSwap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Poll the scanner model file for mtime changes and hot-swap the detector.
/// Runs forever on a dedicated OS thread — never returns.
pub fn watch_scanner_model(
    handle: Arc<ArcSwap<ScannerDetector>>,
    model_path: PathBuf,
    threshold: f64,
    routes: Vec<RouteConfig>,
    poll_interval: Duration,
) {
    let mut last_mtime = std::fs::metadata(&model_path)
        .and_then(|m| m.modified())
        .ok();

    loop {
        std::thread::sleep(poll_interval);

        let current_mtime = match std::fs::metadata(&model_path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => continue,
        };

        if Some(current_mtime) == last_mtime {
            continue;
        }

        match ScannerModel::load(&model_path) {
            Ok(mut model) => {
                model.threshold = threshold;
                let fragment_count = model.fragments.len();
                let detector = ScannerDetector::new(&model, &routes);
                handle.store(Arc::new(detector));
                last_mtime = Some(current_mtime);
                tracing::info!(
                    fragments = fragment_count,
                    "scanner model hot-reloaded"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to reload scanner model; keeping current");
            }
        }
    }
}
