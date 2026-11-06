use super::*;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const DEBOUNCE: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(super) struct RepositoryMonitor {
    last: Option<sherlock_git::RepositorySnapshot>,
    receiver: Option<Receiver<Result<sherlock_git::RepositorySnapshot, String>>>,
    next_poll: Option<Instant>,
    scan_after: Option<Instant>,
    pub(super) error: Option<String>,
    pub(super) worktree_dirty: bool,
}

impl App {
    pub(super) fn request_scan(&mut self) {
        self.automatic_scan_pending = true;
        self.scan_target = Some(self.repo());
        self.monitor.scan_after = None;
    }

    pub(super) fn poll_automatic_scan(&mut self, ctx: &egui::Context) {
        let Some(project) = self.project_root.clone() else {
            return;
        };
        let now = Instant::now();
        // Mirror review uses an explicitly selected set of rewritten branches.
        // Do not silently run an unrestricted scan over the mirror's original refs.
        if self.repo() == project {
            if let Some(receiver) = &self.monitor.receiver {
                match receiver.try_recv() {
                    Ok(Ok(snapshot)) => {
                        self.monitor.receiver = None;
                        if self.monitor.error.is_some()
                            || self
                                .monitor
                                .last
                                .as_ref()
                                .is_some_and(|old| old.refs != snapshot.refs)
                        {
                            if !self.branches.is_empty() {
                                self.branch_snapshot_stale = true;
                            }
                            self.automatic_scan_pending = true;
                            self.scan_target = Some(project.clone());
                            self.monitor.scan_after = Some(now + DEBOUNCE);
                            self.scan_stale = true;
                            self.branches.clear();
                            self.checked.clear();
                            self.history_output = None;
                        }
                        self.monitor.worktree_dirty = snapshot.worktree_dirty;
                        self.monitor.last = Some(snapshot);
                        self.monitor.error = None;
                    }
                    Ok(Err(error)) => {
                        self.monitor.receiver = None;
                        self.monitor.error = Some(error);
                        self.scan_stale = true;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.monitor.receiver = None;
                        self.monitor.error =
                            Some("Repository monitoring stopped unexpectedly.".into());
                        self.scan_stale = true;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            if self.monitor.receiver.is_none()
                && self.monitor.next_poll.is_none_or(|next| now >= next)
            {
                let (tx, rx) = mpsc::channel();
                self.monitor.receiver = Some(rx);
                self.monitor.next_poll = Some(now + POLL_INTERVAL);
                std::thread::spawn(move || {
                    let _ = tx.send(sherlock_git::repository_snapshot(&project));
                });
            }
        } else {
            self.monitor = RepositoryMonitor::default();
        }
        if self.automatic_scan_pending && self.scan_target.as_ref() != Some(&self.repo()) {
            self.automatic_scan_pending = false;
            self.scan_target = None;
        }
        let monitor_ready = self.repo() != *self.project_root.as_ref().unwrap()
            || self.monitor.last.is_some()
            || self.monitor.error.is_some();
        if self.automatic_scan_pending
            && self.receiver.is_none()
            && monitor_ready
            && self.monitor.scan_after.is_none_or(|after| now >= after)
        {
            self.automatic_scan_pending = false;
            self.scan_target = None;
            self.monitor.scan_after = None;
            let repo = self.repo();
            let scanner = self.scanner;
            self.status = format!("Scanning committed history with {}…", scanner.label());
            self.task(move || ResultMessage::Scan(sherlock_scan::scan(&repo, scanner)));
        }
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}
