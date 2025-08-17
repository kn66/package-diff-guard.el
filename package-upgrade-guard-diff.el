;;; package-upgrade-guard-diff.el --- Diff generation logic for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains diff generation logic for package-upgrade-guard.

;;; Code:

(require 'diff)
(require 'package-upgrade-guard-constants)
(require 'package-upgrade-guard-utils)

(defun package-upgrade-guard--show-simple-diff
    (old-content new-content)
  "Show a simple line-by-line comparison when full diff fails."
  (let ((old-lines (split-string old-content "\n" t))
        (new-lines (split-string new-content "\n" t))
        (max-lines package-upgrade-guard--max-diff-lines)
        (shown-lines 0))

    (insert
     (format "  File sizes: %d → %d bytes\n"
             (length old-content)
             (length new-content)))
    (insert
     (format "  Lines: %d → %d\n"
             (length old-lines)
             (length new-lines)))
    (insert "  First few different lines:\n")

    (let ((i 0))
      (while (and (< i (max (length old-lines) (length new-lines)))
                  (< shown-lines max-lines))
        (let ((old-line
               (if (< i (length old-lines))
                   (nth i old-lines)
                 nil))
              (new-line
               (if (< i (length new-lines))
                   (nth i new-lines)
                 nil)))

          (cond
           ;; Both lines exist but are different
           ((and old-line new-line (not (string= old-line new-line)))
            (insert
             (format
              "  -%d: %s\n"
              (1+ i)
              (truncate-string-to-width
               old-line package-upgrade-guard--line-truncate-length)))
            (insert
             (format
              "  +%d: %s\n"
              (1+ i)
              (truncate-string-to-width
               new-line package-upgrade-guard--line-truncate-length)))
            (setq shown-lines (+ shown-lines 2)))
           ;; Line deleted
           ((and old-line (not new-line))
            (insert
             (format
              "  -%d: %s\n"
              (1+ i)
              (truncate-string-to-width
               old-line package-upgrade-guard--line-truncate-length)))
            (setq shown-lines (1+ shown-lines)))
           ;; Line added
           ((and (not old-line) new-line)
            (insert
             (format
              "  +%d: %s\n"
              (1+ i)
              (truncate-string-to-width
               new-line package-upgrade-guard--line-truncate-length)))
            (setq shown-lines (1+ shown-lines))))

          (setq i (1+ i))))

      (when (>= shown-lines max-lines)
        (insert
         (format "  ... [truncated, showing first %d changes] ...\n"
                 package-upgrade-guard--max-diff-lines))))))

(defun package-upgrade-guard--generate-diff (old-dir new-dir)
  "Generate diff between OLD-DIR and NEW-DIR."
  (insert
   (format "Comparing directories:\n  Old: %s\n  New: %s\n\n"
           old-dir
           new-dir))

  (let ((old-files
         (when (file-exists-p old-dir)
           (directory-files-recursively old-dir ".*")))
        (new-files
         (when (file-exists-p new-dir)
           (directory-files-recursively new-dir ".*")))
        (all-files nil))

    ;; Collect all unique file names efficiently
    (let ((file-set (make-hash-table :test 'equal)))
      (dolist (file old-files)
        (let ((rel-name (file-relative-name file old-dir)))
          (puthash rel-name t file-set)))

      (dolist (file new-files)
        (let ((rel-name (file-relative-name file new-dir)))
          (puthash rel-name t file-set)))

      (setq all-files (hash-table-keys file-set)))

    (setq all-files (sort all-files #'string<))

    ;; Generate diff for each file
    (dolist (rel-file all-files)
      (let ((old-file (expand-file-name rel-file old-dir))
            (new-file (expand-file-name rel-file new-dir)))
        (insert (format "\n=== %s ===\n" rel-file))

        (cond
         ((and (file-exists-p old-file) (file-exists-p new-file))
          ;; Both files exist - show diff
          (if (file-directory-p old-file)
              (insert "Directory (skipped)\n")
            (let ((old-content
                   (package-upgrade-guard--safe-read-file old-file))
                  (new-content
                   (package-upgrade-guard--safe-read-file new-file)))
              (if (string= old-content new-content)
                  (insert "No changes\n")
                (insert "File modified - showing unified diff:\n")
                (condition-case err
                    (let ((diff-result
                           (diff-no-select
                            old-file new-file nil 'noasync)))
                      (when diff-result
                        (let ((diff-content
                               (with-current-buffer diff-result
                                 (buffer-string))))
                          (insert diff-content))
                        (kill-buffer diff-result)))
                  (error
                   ;; Fallback: show manual diff using simple line comparison
                   (insert
                    (format "  Diff generation failed: %s\n"
                            (error-message-string err)))
                   (insert "  Showing simple comparison:\n")
                   (package-upgrade-guard--show-simple-diff
                    old-content new-content)))))))
         ((file-exists-p new-file)
          ;; New file
          (insert "New file added:\n")
          (let ((content
                 (package-upgrade-guard--safe-read-file
                  new-file package-upgrade-guard--file-preview-size)))
            (insert content)
            (when (and (not (string-prefix-p "[Error" content))
                       (> (nth 7 (file-attributes new-file))
                          package-upgrade-guard--file-preview-size))
              (insert "\n... [truncated] ..."))))
         ((file-exists-p old-file)
          ;; Deleted file
          (insert "File deleted\n")))))))

(provide 'package-upgrade-guard-diff)

;;; package-upgrade-guard-diff.el ends here
