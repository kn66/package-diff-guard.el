;;; package-upgrade-guard-tar.el --- TAR extraction logic for package-upgrade-guard -*- lexical-binding: t; -*-

;; Copyright (C) 2025 Free Software Foundation, Inc.

;; Author: Package Security Check
;; Keywords: convenience, packages, security

;;; Commentary:

;; This file contains TAR file extraction logic for package-upgrade-guard.

;;; Code:

(require 'package)
(require 'package-upgrade-guard-constants)
(require 'package-upgrade-guard-utils)

;; TAR handling utilities
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

(provide 'package-upgrade-guard-tar)

;;; package-upgrade-guard-tar.el ends here
