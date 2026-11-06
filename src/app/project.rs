use super::*;
use std::path::Path;

impl App {
    /// Replace the whole project session only after the new repository is valid.
    pub(super) fn open_project(&mut self, path: &Path) -> Result<(), String> {
        if self.receiver.is_some() {
            return Err(
                "Wait for the current operation to finish before switching repositories.".into(),
            );
        }
        let root = sherlock_git::open_repository(path)?;
        let repo = root
            .to_str()
            .ok_or("This repository path is not valid UTF-8.")?
            .to_owned();
        let scanner = self.scanner;
        *self = Self::default();
        self.scanner = scanner;
        self.repo = repo;
        self.destination = sherlock_git::suggested_destination(&root)
            .display()
            .to_string();
        self.project_root = Some(root.clone());
        self.automatic_scan_pending = true;
        self.scan_target = Some(root);
        self.status = "Repository opened. Preparing the initial history scan…".into();
        Ok(())
    }

    pub(super) fn choose_project(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open a Git repository")
            .pick_folder()
        {
            if let Err(error) = self.open_project(&path) {
                self.status = error;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_projects_clears_session_and_rejects_invalid_paths() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for dir in [first.path(), second.path()] {
            assert!(std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
        }
        let invalid = tempfile::tempdir().unwrap();
        let mut app = App::default();
        app.open_project(first.path()).unwrap();
        app.search = "prior project".into();
        app.scan_completed = true;
        app.destination = "old destination".into();
        assert!(app.open_project(invalid.path()).is_err());
        assert_eq!(
            app.project_root.as_deref(),
            Some(first.path().canonicalize().unwrap().as_path())
        );
        assert_eq!(app.search, "prior project");
        app.open_project(second.path()).unwrap();
        assert_eq!(
            app.project_root.as_deref(),
            Some(second.path().canonicalize().unwrap().as_path())
        );
        assert!(app.search.is_empty());
        assert!(!app.scan_completed);
        assert_ne!(app.destination, "old destination");
    }

    #[test]
    fn active_background_work_blocks_switching_projects() {
        let mut app = App::default();
        let (_sender, receiver) = std::sync::mpsc::channel();
        app.receiver = Some(receiver);
        assert!(app
            .open_project(Path::new("."))
            .unwrap_err()
            .contains("Wait"));
    }
}
