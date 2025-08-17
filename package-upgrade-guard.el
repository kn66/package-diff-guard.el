;;; package-upgrade-guard.el --- Simple security checker for third-party packages -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Version: 1.0.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: convenience, packages, security

;;; Commentary:

;; Shows diff for all package upgrades/installations to help users review
;; changes before proceeding. Supports both ELPA/MELPA archives and VC packages.

;;; Code:

(require 'package)
(require 'diff)
(require 'vc-git)

;; Constants
(defconst package-upgrade-guard--tar-header-size 512
  "Size of TAR header in bytes.")

(defconst package-upgrade-guard--tar-filename-offset 0
  "Offset for filename in TAR header.")

(defconst package-upgrade-guard--tar-filename-size 100
  "Size of filename field in TAR header.")

(defconst package-upgrade-guard--tar-size-offset 124
  "Offset for file size in TAR header.")

(defconst package-upgrade-guard--tar-size-length 12
  "Length of file size field in TAR header.")

(defconst package-upgrade-guard--max-diff-lines 20
  "Maximum number of diff lines to show.")

(defconst package-upgrade-guard--file-preview-size 500
  "Maximum bytes to show in file preview.")

(defconst package-upgrade-guard--line-truncate-length 80
  "Maximum length for truncated lines in diff output.")

(defconst package-upgrade-guard--buffer-names
  '("*Package Security Diff*"
    "*Package VC Diff*"
    "*Package Contents*")
  "List of buffer names used by package security check.")

(defgroup package-upgrade-guard nil
  "Security checking for package upgrades."
  :group 'package
  :prefix "package-upgrade-guard-")

(defcustom package-upgrade-guard-enabled t
  "Whether to perform security checks before installing packages."
  :type 'boolean
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-temp-dir nil
  "Directory for temporarily storing packages during security checks."
  :type '(choice (const :tag "Default" nil) (directory :tag "Directory"))
  :group 'package-upgrade-guard)

(defcustom package-upgrade-guard-excluded-archives nil
  "List of package archives to exclude from security checks.
Each element should be a string matching an archive name from `package-archives'.
For example: '(\"gnu\" \"nongnu\") to exclude GNU ELPA and NonGNU ELPA."
  :type '(repeat string)
  :group 'package-upgrade-guard)

(defvar package-upgrade-guard--temp-dir nil
  "Actual temporary directory used for security checks.")

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

(defun package-upgrade-guard--package-excluded-p (pkg-desc)
  "Check if package PKG-DESC should be excluded from security checks.
Returns t if the package's archive is in the excluded list."
  (when (and package-upgrade-guard-excluded-archives pkg-desc)
    (let ((archive (package-desc-archive pkg-desc)))
      ;; If archive is nil, try to find it from package-archive-contents
      (when (null archive)
        (let* ((pkg-name (package-desc-name pkg-desc))
               (available (assq pkg-name package-archive-contents)))
          (when available
            (setq archive (package-desc-archive (cadr available))))))
      (and archive
           (member
            archive package-upgrade-guard-excluded-archives)))))


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

(defun package-upgrade-guard--clean-tar-string (raw-string)
  "Clean RAW-STRING by removing null bytes and trimming whitespace."
  (string-trim (replace-regexp-in-string "\0" "" raw-string)))

(defun package-upgrade-guard--read-tar-header-field
    (start offset length)
  "Read tar header field from buffer starting at START with OFFSET and LENGTH."
  (let ((raw
         (buffer-substring (+ start offset) (+ start offset length))))
    (package-upgrade-guard--clean-tar-string raw)))

(defun package-upgrade-guard--parse-tar-size (size-str)
  "Parse SIZE-STR as octal number, returning 0 on error."
  (if (string-empty-p size-str)
      0
    (condition-case nil
        (string-to-number size-str 8)
      (error
       0))))

(defun package-upgrade-guard--clean-tar-filename (filename)
  "Clean FILENAME by removing top-level directory to avoid double nesting."
  (let ((filename-parts (split-string filename "/")))
    (if (> (length filename-parts) 1)
        (mapconcat 'identity (cdr filename-parts) "/")
      filename)))

(defun package-upgrade-guard--extract-tar-file
    (filename size extract-dir)
  "Extract single file from tar with FILENAME, SIZE to EXTRACT-DIR."
  (when (and (> size 0)
             (not (string-suffix-p "/" filename))
             (< (+ (point) size) (point-max)))
    (condition-case err
        (let* ((filename-clean
                (package-upgrade-guard--clean-tar-filename filename))
               (file-path
                (expand-file-name filename-clean extract-dir))
               (file-data
                (buffer-substring (point) (+ (point) size))))
          (make-directory (file-name-directory file-path) t)
          (with-temp-buffer
            (set-buffer-multibyte nil)
            (insert file-data)
            (write-region (point-min) (point-max) file-path
                          nil
                          'silent)))
      (error
       (message "Failed to extract %s: %s"
                filename
                (error-message-string err))))))

(defun package-upgrade-guard--calculate-next-tar-position
    (header-start size)
  "Calculate next tar entry position from HEADER-START and SIZE."
  (let ((next-pos
         (+ header-start package-upgrade-guard--tar-header-size
            (if (> size 0)
                (* package-upgrade-guard--tar-header-size
                   (ceiling (/ size 512.0)))
              0))))
    (if (<= next-pos header-start)
        (point-max)
      next-pos)))

(defun package-upgrade-guard--extract-tar-manually
    (tar-file extract-dir)
  "Extract TAR-FILE to EXTRACT-DIR with proper filename handling."
  (make-directory extract-dir t)

  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert-file-contents-literally tar-file)
    (goto-char (point-min))

    (while (< (point)
              (- (point-max) package-upgrade-guard--tar-header-size))
      (let* ((header-start (point))
             (filename
              (package-upgrade-guard--read-tar-header-field
               header-start
               package-upgrade-guard--tar-filename-offset
               package-upgrade-guard--tar-filename-size)))

        ;; Stop if empty filename (end of archive)
        (if (string-empty-p filename)
            (goto-char (point-max))

          ;; Read file size from header
          (let* ((size-str
                  (package-upgrade-guard--read-tar-header-field
                   header-start
                   package-upgrade-guard--tar-size-offset
                   package-upgrade-guard--tar-size-length))
                 (size
                  (package-upgrade-guard--parse-tar-size size-str)))

            ;; Move to data section
            (goto-char
             (+ header-start package-upgrade-guard--tar-header-size))

            ;; Extract file if it's a regular file
            (package-upgrade-guard--extract-tar-file
             filename size extract-dir)

            ;; Move to next entry
            (goto-char
             (package-upgrade-guard--calculate-next-tar-position
              header-start size))))))))

(defun package-upgrade-guard--download-package-safely (pkg-desc)
  "Download package PKG-DESC to temporary directory without installing."
  (let* ((temp-dir (package-upgrade-guard--get-temp-dir))
         (pkg-name (package-desc-name pkg-desc))
         (pkg-version
          (package-version-join (package-desc-version pkg-desc)))
         (pkg-full-name (format "%s-%s" pkg-name pkg-version))
         (temp-pkg-dir (expand-file-name pkg-full-name temp-dir))
         (location (package-archive-base pkg-desc))
         (file
          (concat
           (package-desc-full-name pkg-desc)
           (package-desc-suffix pkg-desc))))

    ;; Clean up any existing temp directory
    (when (file-exists-p temp-pkg-dir)
      (delete-directory temp-pkg-dir t))

    ;; Download package
    (package--with-response-buffer
      location
      :file file
      (let ((temp-file (expand-file-name file temp-dir)))
        (write-region (point-min) (point-max) temp-file nil 'silent)

        ;; Extract the package
        (cond
         ((string-suffix-p ".tar" file)
          ;; Handle tar files
          (package-upgrade-guard--extract-tar-manually
           temp-file temp-pkg-dir)
          (delete-file temp-file))
         ((string-suffix-p ".el" file)
          ;; Handle single .el files
          (make-directory temp-pkg-dir t)
          (copy-file
           temp-file
           (expand-file-name (format "%s.el" pkg-name) temp-pkg-dir)
           t)
          (delete-file temp-file))
         (t
          (error "Unsupported package format: %s" file)))

        temp-pkg-dir))))

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
                  new-file
                  package-upgrade-guard--file-preview-size)))
            (insert content)
            (when (and (not (string-prefix-p "[Error" content))
                       (> (nth 7 (file-attributes new-file))
                          package-upgrade-guard--file-preview-size))
              (insert "\n... [truncated] ..."))))
         ((file-exists-p old-file)
          ;; Deleted file
          (insert "File deleted\n")))))))

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

(defun package-upgrade-guard--cleanup-diff-buffers ()
  "Clean up all package security check related buffers."
  (dolist (buffer-name package-upgrade-guard--buffer-names)
    (when-let ((buffer (get-buffer buffer-name)))
      (kill-buffer buffer))))

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
                       "Skipping security check for excluded archive: %s"
                       (package-desc-archive new-pkg-desc))
                      (setq approved t))
                  ;; Regular security check
                  (if (and pkg-desc (package-vc-p pkg-desc))
                      ;; VC package - show git diff
                      (setq approved
                            (package-upgrade-guard--show-vc-diff
                             pkg-desc))
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
                     "Auto-approving installation from excluded archive: %s"
                     (package-desc-archive pkg-desc))
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
                     "Auto-approving upgrade from excluded archive: %s"
                     (package-desc-archive pkg-desc))
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
          (let ((total-approved (+ (length approved-installs) (length approved-upgrades))))
            (when (> total-approved 0)
              (message "Proceeding with %d approved package(s):" total-approved)
              (when approved-installs
                (message "  Installing: %s" 
                         (mapconcat (lambda (pkg) (symbol-name (package-desc-name pkg)))
                                   approved-installs ", ")))
              (when approved-upgrades
                (message "  Upgrading: %s"
                         (mapconcat (lambda (pkg) (symbol-name (package-desc-name pkg)))
                                   approved-upgrades ", ")))))
          
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
              (mapcar (lambda (pkg) (symbol-name (package-desc-name pkg))) unapproved-installs)
              (mapcar (lambda (pkg) (symbol-name (package-desc-name pkg))) unapproved-upgrades))))
        (message "Skipped %d rejected package(s): %s"
                 (+ (length unapproved-installs) (length unapproved-upgrades))
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
            (message
             "Skipping security check for excluded archive: %s"
             (package-desc-archive new-pkg-desc))
            (setq approved t))
        ;; Regular security check
        (if (and pkg-desc (package-vc-p pkg-desc))
            ;; VC package - show git diff
            (setq approved
                  (package-upgrade-guard--show-vc-diff pkg-desc))
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

(provide 'package-upgrade-guard)

;;; package-upgrade-guard.el ends here
