# LovelyHawk desktop notices

These notices cover what the desktop executable embeds: the UI bundle, its
fonts and data, and the Tauri application framework. The Rust crates the
executable links are listed by `Cargo.lock`; a complete crate-level SBOM is
still an open release item.

## Tauri 2.12.5 and @tauri-apps/api 2.12.4

- Packages: `tauri` (Rust crate) with `tauri-plugin-dialog` 2.8.4 and
  `tauri-plugin-clipboard-manager` 2.5.0; `@tauri-apps/api` (npm, bundled into the UI)
- Project: https://github.com/tauri-apps/tauri
- Copyright (c) 2017 - Present Tauri Apps Contributors
- Locked by: `Cargo.lock` and `pnpm-lock.yaml`

Tauri is dual-licensed under the MIT License (reproduced in the React section
below with its own copyright line) or the Apache License, Version 2.0, at the
recipient's option; LovelyHawk uses it under the MIT License.

## Microsoft Edge WebView2 Runtime

The page engine is the WebView2 Runtime already installed with Windows. It is
a system component and is not redistributed in the LovelyHawk package.

## React 19.3.1, React DOM 19.3.1, and Scheduler 0.28.0

- Copyright Meta Platforms, Inc. and affiliates.
- Embedded packages: `react`, `react-dom`, `scheduler`
- Locked by: `pnpm-lock.yaml`

These packages are distributed under the MIT License:

```text
MIT License

Copyright (c) Meta Platforms, Inc. and affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## xterm.js 6.0.0, Fit Addon 0.11.0, and Search Addon 0.16.0

- Packages: `@xterm/xterm`, `@xterm/addon-fit`, `@xterm/addon-search`
- Project: https://github.com/xtermjs/xterm.js
- Locked by: `pnpm-lock.yaml`
- Copyright (c) 2017-2019, The xterm.js authors
- Copyright (c) 2014-2016, SourceLair Private Company
- Copyright (c) 2012-2013, Christopher Jeffrey
- Fit Addon copyright (c) 2019, The xterm.js authors
- Search Addon copyright (c) 2017, The xterm.js authors

These packages are distributed under the MIT License:

```text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Inter 4.1

- Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter)
- Source: https://github.com/rsms/inter/releases/tag/v4.1
- Embedded files: `Inter-Regular.ttf`, `Inter-SemiBold.ttf`
- SHA-256: `40d692fce188e4471e2b3cba937be967878f631ad3ebbbdcd587687c7ebe0c82`, `78a843fade9d4612a5567302fb595b56976eb5fcebf4fea5a5912d638bafcde3`

## Cascadia Mono 2407.24

- Copyright 2020 Microsoft Corporation
- Source: https://github.com/microsoft/cascadia-code/releases/tag/v2407.24
- Embedded file: `CascadiaMono.ttf`
- SHA-256: `08026f617eea315caca59898784e999f6cdb2d0c34d2040deeb042bcdc359fa2`

Both font families are distributed under the SIL Open Font License 1.1:

```text
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply to any
document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may include
source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining a
copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components, in
Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or in
the appropriate machine-readable metadata fields within text or binary
files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any Modified
Version, except to acknowledge the contribution(s) of the Copyright
Holder(s) and the Author(s) or with their explicit written permission.

5) The Font Software, modified or unmodified, in part or in whole, must be
distributed entirely under this license, and must not be distributed under
any other license. The requirement for fonts to remain under this license
does not apply to any document created using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are not
met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM OTHER DEALINGS
IN THE FONT SOFTWARE.
```
