<!--
   - SPDX-FileCopyrightText: 2022 Serokell <https://serokell.io>
   - SPDX-License-Identifier: MPL-2.0
   -->

## v0.0.4

* Bundled blst version bumped to v0.3.13

## v0.0.3

* Minor tweaks for GHC 9.8 compatibility.
* Types `Point` and `Affine` now have `PointKind` parameter be role `nominal`, as coercing those between point types will break invariants.
* Bundled blst version bumped to v0.3.11.

## v0.0.2

* Prevent inlining of foreign calls. This fixes a potential efficiency issue,
  but it shouldn't affect correctness.

## v0.0.1

* Initial release
