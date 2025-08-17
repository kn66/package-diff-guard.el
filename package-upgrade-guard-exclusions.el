;;; package-upgrade-guard-exclusions.el --- Package exclusion logic for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains package exclusion checking logic for package-upgrade-guard.

;;; Code:

(require 'package)
(require 'package-upgrade-guard-constants)

(defun package-upgrade-guard--package-excluded-p (pkg-desc)
  "Check if package PKG-DESC should be excluded from security checks.
Returns t if the package's archive or name is in the excluded lists."
  (when pkg-desc
    (let ((pkg-name (package-desc-name pkg-desc))
          (archive (package-desc-archive pkg-desc))
          (excluded-by-name nil)
          (excluded-by-archive nil))

      ;; Check if package name is excluded
      (when package-upgrade-guard-excluded-packages
        (setq excluded-by-name
              (or (member
                   pkg-name package-upgrade-guard-excluded-packages)
                  (member
                   (symbol-name pkg-name)
                   package-upgrade-guard-excluded-packages))))

      ;; Check if archive is excluded
      (when package-upgrade-guard-excluded-archives
        ;; If archive is nil, try to find it from package-archive-contents
        ;; But for VC packages, archive info might not be available
        (when (null archive)
          (let ((available (assq pkg-name package-archive-contents)))
            (when available
              (setq archive
                    (package-desc-archive (cadr available))))))
        (setq excluded-by-archive
              (and archive
                   (member
                    archive
                    package-upgrade-guard-excluded-archives))))

      ;; Return t if excluded by either name or archive
      (or excluded-by-name excluded-by-archive))))

(defun package-upgrade-guard--get-exclusion-reason (pkg-desc)
  "Get human-readable reason for package exclusion."
  (when pkg-desc
    (let ((pkg-name (package-desc-name pkg-desc))
          (archive (package-desc-archive pkg-desc)))

      ;; Check package name exclusion first
      (cond
       ((and package-upgrade-guard-excluded-packages
             (or (member
                  pkg-name package-upgrade-guard-excluded-packages)
                 (member
                  (symbol-name pkg-name)
                  package-upgrade-guard-excluded-packages)))
        (format "excluded package '%s'" pkg-name))

       ;; Check archive exclusion
       ((and
         package-upgrade-guard-excluded-archives
         (progn
           ;; If archive is nil, try to find it from package-archive-contents
           (when (null archive)
             (let ((available
                    (assq pkg-name package-archive-contents)))
               (when available
                 (setq archive
                       (package-desc-archive (cadr available))))))
           (and archive
                (member
                 archive package-upgrade-guard-excluded-archives))))
        (format "excluded archive '%s'" archive))

       (t
        "unknown reason")))))

(provide 'package-upgrade-guard-exclusions)

;;; package-upgrade-guard-exclusions.el ends here
