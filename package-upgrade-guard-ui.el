;;; package-upgrade-guard-ui.el --- User interface functions for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains user interface and display functions for package-upgrade-guard.

;;; Code:

(require 'diff)
(require 'vc-git)
(require 'package-upgrade-guard-constants)
(require 'package-upgrade-guard-utils)
(require 'package-upgrade-guard-exclusions)
(require 'package-upgrade-guard-tar)
(require 'package-upgrade-guard-diff)

(defun package-upgrade-guard--show-tarball-diff (pkg-desc)
  "Show diff for tarball package PKG-DESC."
  (let* ((pkg-name (package-desc-name pkg-desc))
         (old-dir
          (package-upgrade-guard--find-installed-package-dir
           pkg-name))
         (temp-dir
          (package-upgrade-guard--download-package-safely pkg-desc)))

    (if (not old-dir)
        ;; New package - show contents
        (progn
          (message "New package %s - showing contents..." pkg-name)
          (package-upgrade-guard--show-package-contents temp-dir)
          (package-upgrade-guard--ask-user-approval
           pkg-desc "install new package"))
      ;; Existing package - show diff
      (let ((diff-buffer
             (get-buffer-create "*Package Security Diff*"))
            (old-version
             (package-upgrade-guard--get-version-from-dir old-dir))
            (new-version
             (package-version-join (package-desc-version pkg-desc))))
        (with-current-buffer diff-buffer
          (erase-buffer)
          (insert (format "Diff for package %s:\n" pkg-name))
          (insert
           (format "Old version: %s\n" (or old-version "unknown")))
          (insert (format "New version: %s\n\n" new-version))

          ;; Generate diff
          (package-upgrade-guard--generate-diff old-dir temp-dir)

          (diff-mode)
          (goto-char (point-min)))

        (display-buffer diff-buffer)
        (package-upgrade-guard--ask-user-approval
         pkg-desc "upgrade package")))))

(defun package-upgrade-guard--show-vc-diff (pkg-desc)
  "Show git diff for VC package PKG-DESC.
Returns t if user approves, nil if rejected."
  (let* ((pkg-dir (package-desc-dir pkg-desc))
         (pkg-name (package-desc-name pkg-desc))
         (default-directory pkg-dir))

    (unless (and pkg-dir (file-directory-p pkg-dir))
      (error "VC package directory not found: %s" pkg-dir))

    (unless (file-exists-p (expand-file-name ".git" pkg-dir))
      (error "Not a git repository: %s" pkg-dir))

    (let ((diff-buffer (get-buffer-create "*Package VC Diff*")))
      (with-current-buffer diff-buffer
        (erase-buffer)
        (insert (format "Git diff for VC package %s:\n" pkg-name))
        (insert (format "Repository: %s\n\n" pkg-dir))

        ;; Show current status
        (insert "=== Git Status ===\n")
        (condition-case err
            (call-process "git" nil t nil "status" "--porcelain")
          (error
           (insert (format "Error getting git status: %s\n" err))))

        ;; Fetch latest changes
        (insert "\n=== Fetching latest changes ===\n")
        (condition-case err
            (progn
              (call-process "git" nil t nil "fetch")
              (insert "Fetch completed\n"))
          (error
           (insert (format "Error fetching: %s\n" err))))

        ;; Show what commits will be pulled
        (insert "\n=== New commits to be pulled ===\n")
        (condition-case err
            (let ((result
                   (call-process "git"
                                 nil
                                 t
                                 nil
                                 "log"
                                 "--oneline"
                                 "HEAD..origin/HEAD")))
              (when (and (= result 0)
                         (= (line-beginning-position)
                            (line-end-position)))
                (insert "No new commits\n")))
          (error
           (insert (format "Error getting commit log: %s\n" err))))

        ;; Show detailed diff
        (insert "\n=== Detailed diff ===\n")
        (condition-case err
            (let ((result
                   (call-process "git"
                                 nil
                                 t
                                 nil
                                 "diff"
                                 "HEAD..origin/HEAD")))
              (when (and (= result 0)
                         (= (line-beginning-position)
                            (line-end-position)))
                (insert "No changes in diff\n")))
          (error
           (insert (format "Error getting diff: %s\n" err))))

        (goto-char (point-min)))

      (display-buffer diff-buffer)
      (package-upgrade-guard--ask-user-approval
       pkg-desc "upgrade VC package"))))

(defun package-upgrade-guard--show-package-contents (pkg-dir)
  "Show contents of package directory PKG-DIR."
  (let ((contents-buffer (get-buffer-create "*Package Contents*")))
    (with-current-buffer contents-buffer
      (erase-buffer)
      (insert (format "Contents of new package in %s:\n\n" pkg-dir))

      ;; List files
      (insert "Files:\n")
      (condition-case nil
          (dolist (file (directory-files-recursively pkg-dir ".*"))
            (insert
             (format "  %s\n" (file-relative-name file pkg-dir))))
        (error
         (insert "  [Error listing files]\n")))

      ;; Show main .el file if it exists
      (let ((main-el-files
             (condition-case nil
                 (directory-files pkg-dir nil "\\.el$")
               (error
                nil))))
        (when main-el-files
          (insert "\n--- Main .el file preview ---\n")
          (let ((main-file
                 (expand-file-name (car main-el-files) pkg-dir)))
            (let ((content
                   (package-upgrade-guard--safe-read-file
                    main-file
                    package-upgrade-guard--file-preview-size)))
              (insert content)
              (when (and (not (string-prefix-p "[Error" content))
                         (> (nth 7 (file-attributes main-file))
                            package-upgrade-guard--file-preview-size))
                (insert "\n... [truncated] ...")))))))

    (display-buffer contents-buffer)))

(defun package-upgrade-guard--ask-user-approval (pkg-desc action)
  "Ask user for approval to ACTION on PKG-DESC.
Automatically cleans up diff buffers after approval/rejection."
  (let ((pkg-name (package-desc-name pkg-desc))
        (result nil))
    (unwind-protect
        (progn
          ;; Clear any pending input to avoid double input issues
          (discard-input)

          ;; Use yes-or-no-p for simpler input handling
          (let ((prompt
                 (format "Security check: Approve %s for %s? "
                         action
                         pkg-name)))
            (setq result (yes-or-no-p prompt))))

      ;; Cleanup diff buffers after decision
      (package-upgrade-guard--cleanup-diff-buffers))
    result))

(provide 'package-upgrade-guard-ui)

;;; package-upgrade-guard-ui.el ends here