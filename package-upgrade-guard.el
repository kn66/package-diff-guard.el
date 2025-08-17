;;; package-upgrade-guard.el --- Simple security checker for third-party packages -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Version: 1.2.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: convenience, packages, security

;;; Commentary:

;; Shows diff for all package upgrades/installations to help users review
;; changes before proceeding. Supports both ELPA/MELPA archives and VC packages.

;;; Code:

(require 'package)
(require 'package-upgrade-guard-constants)
(require 'package-upgrade-guard-utils)
(require 'package-upgrade-guard-exclusions)
(require 'package-upgrade-guard-tar)
(require 'package-upgrade-guard-diff)
(require 'package-upgrade-guard-ui)

;;;###autoload
(define-minor-mode package-upgrade-guard-mode
  "Enable security checking for third-party package upgrades."
  :global t
  :init-value
  nil
  (if package-upgrade-guard-mode
      (package-upgrade-guard--enable)
    (package-upgrade-guard--disable)))

(defun package-upgrade-guard--enable ()
  "Enable security check advices."
  (advice-add
   'package-upgrade
   :around #'package-upgrade-guard--advice-package-upgrade)
  (advice-add
   'package-upgrade-all
   :around #'package-upgrade-guard--advice-package-upgrade-all)
  (advice-add
   'package-menu-execute
   :around #'package-upgrade-guard--advice-package-menu-execute)
  (advice-add
   'package-vc-upgrade
   :around #'package-upgrade-guard--advice-package-vc-upgrade)
  (message "Package diff guard enabled"))

(defun package-upgrade-guard--disable ()
  "Disable security check advices."
  (advice-remove
   'package-upgrade #'package-upgrade-guard--advice-package-upgrade)
  (advice-remove
   'package-upgrade-all
   #'package-upgrade-guard--advice-package-upgrade-all)
  (advice-remove
   'package-menu-execute
   #'package-upgrade-guard--advice-package-menu-execute)
  (advice-remove
   'package-vc-upgrade
   #'package-upgrade-guard--advice-package-vc-upgrade)
  (package-upgrade-guard--cleanup-temp-dir)
  (package-upgrade-guard--cleanup-diff-buffers)
  (message "Package diff guard disabled"))

(defun package-upgrade-guard--advice-package-upgrade (orig-fun name)
  "Advice for `package-upgrade' with diff checking."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun name)
    (let* ((package
            (if (symbolp name)
                name
              (intern name)))
           (approved nil))

      ;; Perform diff check for all packages
      (condition-case err
          (progn
            (let ((pkg-desc (cadr (assq package package-alist)))
                  (available (assq package package-archive-contents)))
              ;; Check the new version from archive contents for exclusion
              (let ((new-pkg-desc
                     (when available
                       (cadr available))))
                (if (package-upgrade-guard--package-excluded-p
                     new-pkg-desc)
                    ;; Package is excluded - skip security check
                    (progn
                      (message
                       "Skipping security check: %s"
                       (package-upgrade-guard--get-exclusion-reason
                        new-pkg-desc))
                      (setq approved t))
                  ;; Regular security check
                  (if (and pkg-desc (package-vc-p pkg-desc))
                      ;; VC package - check exclusion first
                      (if (package-upgrade-guard--package-excluded-p
                           pkg-desc)
                          (progn
                            (message
                             "Skipping security check: %s"
                             (package-upgrade-guard--get-exclusion-reason
                              pkg-desc))
                            (setq approved t))
                        ;; VC package - show git diff
                        (setq approved
                              (package-upgrade-guard--show-vc-diff
                               pkg-desc)))
                    ;; Regular package
                    (when available
                      (setq approved
                            (package-upgrade-guard--show-tarball-diff
                             new-pkg-desc)))))))

            (if approved
                (progn
                  (message
                   "Diff check passed for %s. Proceeding with upgrade..."
                   package)
                  (funcall orig-fun name))
              (message
               "Diff check rejected for %s. Upgrade cancelled."
               package)))

        (error
         (message "Diff check failed for %s: %s"
                  package
                  (error-message-string err))
         (when
             (y-or-n-p
              (format
               "Continue with upgrade of %s despite diff check failure? "
               package))
           (funcall orig-fun name)))))))

(defun package-upgrade-guard--advice-package-upgrade-all
    (orig-fun &optional query)
  "Advice for `package-upgrade-all' with diff checking."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun query)
    (package-refresh-contents)
    (let ((upgradeable (package--upgradeable-packages))
          (upgraded 0))

      (if (not upgradeable)
          (message "No packages to upgrade")
        ;; Ask for overall confirmation first (like original package-upgrade-all)
        (when
            (and
             query
             (not
              (yes-or-no-p
               (format
                "Diff check %d package(s) individually and upgrade? "
                (length upgradeable)))))
          (user-error "Upgrade aborted"))

        (message "Proceeding with individual diff checks...")

        (dolist (package-name upgradeable)
          (message "Checking package %d/%d: %s"
                   (1+ upgraded)
                   (length upgradeable)
                   package-name)
          (condition-case err
              (when (package-upgrade-guard--upgrade-single-package
                     package-name)
                (setq upgraded (1+ upgraded)))
            (error
             (message "Failed to upgrade %s: %s"
                      package-name
                      (error-message-string err)))))

        (message
         "Diff-checked upgrade completed: %d/%d packages upgraded"
         upgraded (length upgradeable))))))

(defun package-upgrade-guard--advice-package-menu-execute
    (orig-fun &optional noquery)
  "Advice for `package-menu-execute' with diff checking."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun noquery)
    ;; Extract packages marked for installation/upgrade
    (let (install-list
          upgrade-list)
      (save-excursion
        (goto-char (point-min))
        (while (not (eobp))
          (let ((cmd (char-after))
                (pkg-desc (tabulated-list-get-id)))
            (when (and pkg-desc (eq cmd ?I))
              (push pkg-desc install-list))
            (when (and pkg-desc (eq cmd ?U))
              (push pkg-desc upgrade-list)))
          (forward-line)))

      ;; All packages will be checked

      ;; If no packages to check, proceed normally
      (if (not (or install-list upgrade-list))
          (funcall orig-fun noquery)

        ;; Perform diff checks for each package
        (let ((approved-installs nil)
              (approved-upgrades nil))

          ;; Check installations
          (dolist (pkg-desc install-list)
            (let ((pkg-name (package-desc-name pkg-desc)))
              (message "Diff checking installation: %s" pkg-name)
              (if (package-upgrade-guard--package-excluded-p pkg-desc)
                  ;; Package is excluded - auto-approve
                  (progn
                    (message
                     "Auto-approving installation: %s"
                     (package-upgrade-guard--get-exclusion-reason
                      pkg-desc))
                    (push pkg-desc approved-installs))
                ;; Regular security check
                (when (package-upgrade-guard--show-tarball-diff
                       pkg-desc)
                  (push pkg-desc approved-installs)))))

          ;; Check upgrades
          (dolist (pkg-desc upgrade-list)
            (let ((pkg-name (package-desc-name pkg-desc)))
              (message "Diff checking upgrade: %s" pkg-name)
              (if (package-upgrade-guard--package-excluded-p pkg-desc)
                  ;; Package is excluded - auto-approve
                  (progn
                    (message
                     "Auto-approving upgrade: %s"
                     (package-upgrade-guard--get-exclusion-reason
                      pkg-desc))
                    (push pkg-desc approved-upgrades))
                ;; Regular security check
                (if (package-vc-p pkg-desc)
                    (when (package-upgrade-guard--show-vc-diff
                           pkg-desc)
                      (push pkg-desc approved-upgrades))
                  (when (package-upgrade-guard--show-tarball-diff
                         pkg-desc)
                    (push pkg-desc approved-upgrades))))))

          ;; Remove unapproved packages from the marked list
          (when (or (< (length approved-installs)
                       (length install-list))
                    (< (length approved-upgrades)
                       (length upgrade-list)))
            (package-upgrade-guard--unmark-unapproved-packages
             install-list
             approved-installs
             upgrade-list
             approved-upgrades))

          ;; Show summary of approved packages before execution
          (let ((total-approved
                 (+ (length approved-installs)
                    (length approved-upgrades))))
            (when (> total-approved 0)
              (message "Proceeding with %d approved package(s):"
                       total-approved)
              (when approved-installs
                (message "  Installing: %s"
                         (mapconcat (lambda (pkg)
                                      (symbol-name
                                       (package-desc-name pkg)))
                                    approved-installs
                                    ", ")))
              (when approved-upgrades
                (message "  Upgrading: %s"
                         (mapconcat (lambda (pkg)
                                      (symbol-name
                                       (package-desc-name pkg)))
                                    approved-upgrades
                                    ", ")))))

          ;; Proceed with execution (only approved packages will be processed)
          (funcall orig-fun noquery))))))

(defun package-upgrade-guard--unmark-unapproved-packages
    (all-installs approved-installs all-upgrades approved-upgrades)
  "Unmark packages that were not approved during security check."
  (let ((unapproved-installs
         (cl-set-difference all-installs approved-installs))
        (unapproved-upgrades
         (cl-set-difference all-upgrades approved-upgrades)))

    (save-excursion
      (goto-char (point-min))
      (while (not (eobp))
        (let ((cmd (char-after))
              (pkg-desc (tabulated-list-get-id)))
          (when (and pkg-desc
                     (or (and (eq cmd ?I)
                              (member pkg-desc unapproved-installs))
                         (and (eq cmd ?U)
                              (member pkg-desc unapproved-upgrades))))
            ;; Unmark this package
            (tabulated-list-put-tag " " t)))
        (forward-line)))

    (when (or unapproved-installs unapproved-upgrades)
      (let ((unapproved-names
             (append
              (mapcar
               (lambda (pkg)
                 (symbol-name (package-desc-name pkg)))
               unapproved-installs)
              (mapcar
               (lambda (pkg)
                 (symbol-name (package-desc-name pkg)))
               unapproved-upgrades))))
        (message "Skipped %d rejected package(s): %s"
                 (+ (length unapproved-installs)
                    (length unapproved-upgrades))
                 (mapconcat 'identity unapproved-names ", "))))))

(defun package-upgrade-guard--upgrade-single-package (package-name)
  "Upgrade single package PACKAGE-NAME with diff check."
  (let* ((pkg-desc (cadr (assq package-name package-alist)))
         (available (assq package-name package-archive-contents))
         (approved nil))

    ;; Check the new version from archive contents for exclusion
    (let ((new-pkg-desc
           (when available
             (cadr available))))
      (if (package-upgrade-guard--package-excluded-p new-pkg-desc)
          ;; Package is excluded - skip security check
          (progn
            (message "Skipping security check: %s"
                     (package-upgrade-guard--get-exclusion-reason
                      new-pkg-desc))
            (setq approved t))
        ;; Regular security check
        (if (and pkg-desc (package-vc-p pkg-desc))
            ;; VC package - check exclusion first
            (if (package-upgrade-guard--package-excluded-p pkg-desc)
                (progn
                  (message
                   "Skipping security check: %s"
                   (package-upgrade-guard--get-exclusion-reason
                    pkg-desc))
                  (setq approved t))
              ;; VC package - show git diff
              (setq approved
                    (package-upgrade-guard--show-vc-diff pkg-desc)))
          ;; Regular package
          (when available
            (setq approved
                  (package-upgrade-guard--show-tarball-diff
                   new-pkg-desc))))))

    (when approved
      ;; Call package-upgrade directly without advice to avoid double prompting
      (let ((package-upgrade-guard-enabled nil))
        (package-upgrade package-name))
      t)))

(defun package-upgrade-guard--advice-package-vc-upgrade
    (orig-fun &optional pkg-name)
  "Advice for `package-vc-upgrade' with diff checking."
  (if (not package-upgrade-guard-enabled)
      (funcall orig-fun pkg-name)
    (let*
        ((pkg-desc
          (cond
           ;; If pkg-name is already a package-desc, use it directly
           ((and pkg-name (package-desc-p pkg-name))
            pkg-name)
           ;; If pkg-name is a symbol or string, find the package-desc
           (pkg-name
            (let ((package-name
                   (if (symbolp pkg-name)
                       pkg-name
                     (intern pkg-name))))
              (cadr (assq package-name package-alist))))
           ;; If no pkg-name provided, call original function (it will prompt)
           (t
            (funcall orig-fun))))
         (approved nil))

      ;; Only proceed if we have a package-desc or if original function was called
      (if (package-desc-p pkg-desc)
          (let ((package-name (package-desc-name pkg-desc)))
            (condition-case err
                (if (package-upgrade-guard--package-excluded-p
                     pkg-desc)
                    ;; Package is excluded - skip security check
                    (progn
                      (message
                       "Skipping security check: %s"
                       (package-upgrade-guard--get-exclusion-reason
                        pkg-desc))
                      (setq approved t))
                  ;; Regular security check for VC packages
                  (setq approved
                        (package-upgrade-guard--show-vc-diff
                         pkg-desc)))
              (error
               (message "Diff check failed for VC package %s: %s"
                        package-name
                        (error-message-string err))
               (when
                   (y-or-n-p
                    (format
                     "Continue with upgrade of %s despite diff check failure? "
                     package-name))
                 (setq approved t))))

            (if approved
                (progn
                  (message
                   "Diff check passed for VC package %s. Proceeding with upgrade..."
                   package-name)
                  ;; Call the original function with package-upgrade-guard disabled
                  (let ((package-upgrade-guard-enabled nil))
                    (funcall orig-fun pkg-desc)))
              (message
               "Diff check rejected for VC package %s. Upgrade cancelled."
               package-name)))
        ;; If we couldn't get a package-desc, we already called the original function above
        nil))))

(provide 'package-upgrade-guard)

;;; package-upgrade-guard.el ends here
