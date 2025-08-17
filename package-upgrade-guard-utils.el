;;; package-upgrade-guard-utils.el --- Utility functions for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains utility functions for package-upgrade-guard.

;;; Code:

(require 'package-upgrade-guard-constants)

;; Temporary directory management
(defun package-upgrade-guard--get-temp-dir ()
  "Get or create the temporary directory for security checks."
  (unless package-upgrade-guard--temp-dir
    (setq package-upgrade-guard--temp-dir
          (or package-upgrade-guard-temp-dir
              (expand-file-name "package-upgrade-guard"
                                temporary-file-directory))))
  (condition-case err
      (progn
        (unless (file-exists-p package-upgrade-guard--temp-dir)
          (make-directory package-upgrade-guard--temp-dir t))
        package-upgrade-guard--temp-dir)
    (error
     (error
      "Failed to create temporary directory %s: %s"
      package-upgrade-guard--temp-dir
      (error-message-string err)))))

(defun package-upgrade-guard--cleanup-temp-dir ()
  "Clean up temporary directory."
  (when (and package-upgrade-guard--temp-dir
             (file-exists-p package-upgrade-guard--temp-dir))
    (condition-case err
        (delete-directory package-upgrade-guard--temp-dir t)
      (error
       (message "Warning: Failed to cleanup temp directory %s: %s"
                package-upgrade-guard--temp-dir
                (error-message-string err))))))

;; File handling utilities
(defun package-upgrade-guard--safe-read-file
    (file-path &optional max-size)
  "Safely read FILE-PATH with optional MAX-SIZE limit, returning content or error message."
  (condition-case err
      (with-temp-buffer
        (if max-size
            (insert-file-contents file-path nil nil max-size)
          (insert-file-contents file-path))
        (buffer-string))
    (error
     (format "[Error reading file: %s]" (error-message-string err)))))

;; Package directory utilities
(defun package-upgrade-guard--find-installed-package-dir (pkg-name)
  "Find installed third-party package directory for PKG-NAME."
  (let ((pkg-name-str (symbol-name pkg-name))
        (elpa-dirs (list package-user-dir)))

    ;; Add system package directories if they exist
    (when (boundp 'package-directory-list)
      (setq elpa-dirs (append elpa-dirs package-directory-list)))

    ;; Search for installed ELPA packages
    (catch 'found
      (dolist (elpa-dir elpa-dirs)
        (when (and elpa-dir (file-directory-p elpa-dir))
          (dolist (dir (directory-files elpa-dir t))
            (when (and
                   (file-directory-p dir)
                   (not
                    (member (file-name-nondirectory dir) '("." "..")))
                   ;; Match package name at start of directory name
                   (string-match
                    (concat
                     "^"
                     (regexp-quote pkg-name-str) "-[0-9]")
                    (file-name-nondirectory dir)))
              (throw 'found dir))))))))

(defun package-upgrade-guard--get-version-from-dir (pkg-dir)
  "Extract version from package directory name."
  (when pkg-dir
    (let ((dir-name (file-name-nondirectory pkg-dir)))
      (when (string-match
             "-\\([0-9][^-]*\\)\\(?:-[0-9]+\\)?$" dir-name)
        (match-string 1 dir-name)))))

;; Buffer management utilities
(defun package-upgrade-guard--cleanup-diff-buffers ()
  "Clean up all package security check related buffers."
  (dolist (buffer-name package-upgrade-guard--buffer-names)
    (when-let ((buffer (get-buffer buffer-name)))
      (kill-buffer buffer))))

(provide 'package-upgrade-guard-utils)

;;; package-upgrade-guard-utils.el ends here