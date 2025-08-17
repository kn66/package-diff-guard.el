;;; package-upgrade-guard-constants.el --- Constants and customization for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains constants and customization variables for package-upgrade-guard.

;;; Code:

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

;; Customization group
(defgroup package-upgrade-guard nil
  "Security checking for package upgrades."
  :group 'package
  :prefix "package-upgrade-guard-")

;; Customization variables
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

(defcustom package-upgrade-guard-excluded-packages nil
  "List of package names to exclude from security checks.
Each element should be a symbol or string matching a package name.
For example: '(magit org-mode helm) to exclude specific packages."
  :type '(repeat (choice symbol string))
  :group 'package-upgrade-guard)

;; Internal variables
(defvar package-upgrade-guard--temp-dir nil
  "Actual temporary directory used for security checks.")

(provide 'package-upgrade-guard-constants)

;;; package-upgrade-guard-constants.el ends here
